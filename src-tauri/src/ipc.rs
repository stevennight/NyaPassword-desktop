//! Local IPC endpoints that only the current user can open: on Windows a named
//! pipe whose DACL grants access to the user's SID alone (remote clients are
//! rejected, and the first instance is created exclusively so a squatter is
//! detected instead of shared); on macOS / Linux a Unix socket with mode 0600.
//! Used by the ssh-agent and by the browser bridge (native messaging host ⇄ app).

use std::io;

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

/// One accepted or opened connection.
pub type Conn = Box<dyn Stream>;

/// The process on the other end, if the OS tells us (shown in confirmations).
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Peer {
    pub pid: Option<u32>,
    /// Full path of the executable.
    pub exe: String,
    /// Executable of the parent process (e.g. `git.exe` for `ssh-keygen.exe`).
    pub parent_exe: String,
}

impl Peer {
    /// "ssh-keygen.exe（git.exe）" for the prompt; empty when unknown.
    pub fn describe(&self) -> String {
        let name = |p: &str| {
            std::path::Path::new(p)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        let exe = name(&self.exe);
        let parent = name(&self.parent_exe);
        match (exe.is_empty(), parent.is_empty()) {
            (true, _) => self.pid.map(|p| format!("PID {p}")).unwrap_or_default(),
            (false, true) => exe,
            (false, false) => format!("{exe}（{parent}）"),
        }
    }
}

/// Reads one `u32` big-endian length-prefixed message. `Ok(None)` at a clean end of stream.
pub async fn read_frame<R: AsyncRead + Unpin + ?Sized>(
    r: &mut R,
    max: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message of {len} bytes is too long"),
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

pub async fn write_frame<W: AsyncWrite + Unpin + ?Sized>(w: &mut W, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too long"))?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    w.write_all(&out).await?;
    w.flush().await
}

pub use imp::{connect, Listener};

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;

    use super::{Conn, Peer};
    use crate::platform::windows::{current_user_sid, parent_pid, process_image};

    const ERROR_PIPE_BUSY: i32 = 231;

    /// `\\.\pipe\<name>`.
    pub fn display(name: &str) -> String {
        format!(r"\\.\pipe\{name}")
    }

    /// A security descriptor granting full access to the current user only.
    struct UserOnly {
        sd: PSECURITY_DESCRIPTOR,
        sa: Box<SECURITY_ATTRIBUTES>,
    }

    // SAFETY: the descriptor is immutable after creation and freed once, on drop.
    unsafe impl Send for UserOnly {}
    unsafe impl Sync for UserOnly {}

    impl UserOnly {
        fn new() -> io::Result<Self> {
            let sid = current_user_sid().map_err(io::Error::other)?;
            // protected DACL (no inheritance), one ACE: generic all for the user
            let sddl = HSTRING::from(format!("D:P(A;;GA;;;{sid})"));
            let mut sd = PSECURITY_DESCRIPTOR::default();
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    &sddl,
                    SDDL_REVISION_1,
                    &mut sd,
                    None,
                )
            }
            .map_err(|e| io::Error::other(e.message()))?;
            let sa = Box::new(SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            });
            Ok(Self { sd, sa })
        }

        fn ptr(&self) -> *mut c_void {
            &*self.sa as *const SECURITY_ATTRIBUTES as *mut c_void
        }
    }

    impl Drop for UserOnly {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.sd.0)));
            }
        }
    }

    pub struct Listener {
        path: String,
        security: UserOnly,
        next: NamedPipeServer,
    }

    fn create(path: &str, security: &UserOnly, first: bool) -> io::Result<NamedPipeServer> {
        let mut o = ServerOptions::new();
        o.first_pipe_instance(first).reject_remote_clients(true);
        // SAFETY: the pointer is a valid SECURITY_ATTRIBUTES that outlives the call.
        unsafe { o.create_with_security_attributes_raw(path, security.ptr()) }
    }

    impl Listener {
        /// Creates the pipe `name`. Fails (access denied / pipe busy) when
        /// another process already owns that name.
        pub fn bind(name: &str) -> io::Result<Self> {
            let path = display(name);
            let security = UserOnly::new()?;
            let next = create(&path, &security, true)?;
            Ok(Self {
                path,
                security,
                next,
            })
        }

        pub async fn accept(&mut self) -> io::Result<(Conn, Peer)> {
            self.next.connect().await?;
            let fresh = create(&self.path, &self.security, false)?;
            let conn = std::mem::replace(&mut self.next, fresh);
            let peer = peer_of(HANDLE(conn.as_raw_handle()));
            Ok((Box::new(conn), peer))
        }
    }

    fn peer_of(h: HANDLE) -> Peer {
        let mut pid = 0u32;
        if unsafe { GetNamedPipeClientProcessId(h, &mut pid) }.is_err() {
            return Peer::default();
        }
        Peer {
            pid: Some(pid),
            exe: process_image(pid).unwrap_or_default(),
            parent_exe: parent_pid(pid).and_then(process_image).unwrap_or_default(),
        }
    }

    pub async fn connect(name: &str) -> io::Result<Conn> {
        let path = display(name);
        for _ in 0..100 {
            match ClientOptions::new().open(&path) {
                Ok(c) => return Ok(Box::new(c)),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    tokio::time::sleep(Duration::from_millis(50)).await
                }
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "pipe busy"))
    }
}

#[cfg(unix)]
mod imp {
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use tokio::net::{UnixListener, UnixStream};

    use super::{Conn, Peer};

    pub struct Listener {
        inner: UnixListener,
        path: PathBuf,
    }

    impl Listener {
        /// Binds the socket at `path` (mode 0600). A stale socket file is
        /// replaced; a live one (another agent answers) is an error.
        pub fn bind(path: &str) -> io::Result<Self> {
            let path = PathBuf::from(path);
            if path.exists() {
                if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!("{} is in use by another process", path.display()),
                    ));
                }
                std::fs::remove_file(&path)?;
            }
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let inner = UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Self { inner, path })
        }

        pub async fn accept(&mut self) -> io::Result<(Conn, Peer)> {
            let (s, _) = self.inner.accept().await?;
            let pid = s.peer_cred().ok().and_then(|c| c.pid()).map(|p| p as u32);
            let exe = pid.map(exe_of).unwrap_or_default();
            Ok((
                Box::new(s),
                Peer {
                    pid,
                    exe,
                    parent_exe: String::new(),
                },
            ))
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[cfg(target_os = "linux")]
    fn exe_of(pid: u32) -> String {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    }

    #[cfg(not(target_os = "linux"))]
    fn exe_of(_pid: u32) -> String {
        String::new()
    }

    pub async fn connect(path: &str) -> io::Result<Conn> {
        Ok(Box::new(UnixStream::connect(path).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique(name: &str) -> String {
        let n = format!(
            "npw-test-{name}-{}-{}",
            std::process::id(),
            npw_model::new_id()
        );
        if cfg!(windows) {
            n
        } else {
            std::env::temp_dir().join(n).display().to_string()
        }
    }

    #[test]
    fn frames_round_trip_and_peer_is_us() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let name = unique("ipc");
            let mut l = Listener::bind(&name).unwrap();
            // the name is taken now: a second exclusive bind must fail
            assert!(Listener::bind(&name).is_err());
            let server = tokio::spawn(async move {
                let (mut c, peer) = l.accept().await.unwrap();
                let m = read_frame(&mut c, 1024).await.unwrap().unwrap();
                write_frame(&mut c, &[m.as_slice(), b"!"].concat())
                    .await
                    .unwrap();
                assert!(read_frame(&mut c, 1024).await.unwrap().is_none());
                peer
            });
            let mut c = connect(&name).await.unwrap();
            write_frame(&mut c, b"hello").await.unwrap();
            assert_eq!(read_frame(&mut c, 1024).await.unwrap().unwrap(), b"hello!");
            drop(c);
            let peer = server.await.unwrap();
            if cfg!(any(windows, target_os = "linux")) {
                assert_eq!(peer.pid, Some(std::process::id()));
                assert!(!peer.exe.is_empty());
            }
        });
    }

    #[test]
    fn oversized_frames_are_refused() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (mut a, mut b) = tokio::io::duplex(64);
            a.write_all(&100u32.to_be_bytes()).await.unwrap();
            assert!(read_frame(&mut b, 10).await.is_err());
        });
    }

    #[test]
    fn peer_description() {
        let p = Peer {
            pid: Some(7),
            exe: r"C:\Program Files\Git\usr\bin\ssh-keygen.exe"
                .replace('\\', std::path::MAIN_SEPARATOR_STR),
            parent_exe: r"C:\Program Files\Git\cmd\git.exe"
                .replace('\\', std::path::MAIN_SEPARATOR_STR),
        };
        assert_eq!(p.describe(), "ssh-keygen.exe（git.exe）");
        assert_eq!(
            Peer {
                pid: Some(7),
                ..Default::default()
            }
            .describe(),
            "PID 7"
        );
    }
}
