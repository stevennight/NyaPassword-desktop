; NSIS installer hooks (tauri.conf.json > bundle > windows > nsis > installerHooks).
; Uninstalling removes the browser-bridge native messaging host registration
; (HKCU, written by the app when the browser bridge is turned on). If the
; uninstaller runs as part of an update, the app registers it again on its
; next start.

!macro NSIS_HOOK_POSTUNINSTALL
  DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\app.nya.password"
  DeleteRegKey HKCU "Software\Microsoft\Edge\NativeMessagingHosts\app.nya.password"
  DeleteRegKey HKCU "Software\Chromium\NativeMessagingHosts\app.nya.password"
!macroend
