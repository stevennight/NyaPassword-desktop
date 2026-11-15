#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

int npw_touch_id_available(void) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        return [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                                    error:&error] ? 1 : 0;
    }
}

int npw_touch_id_authenticate(const char *reason) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                                  error:&error]) {
            return -2;
        }

        NSString *localizedReason = [[NSString alloc] initWithUTF8String:reason ?: "NyaPassword"];
        dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
        __block BOOL accepted = NO;
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                 localizedReason:localizedReason
                           reply:^(BOOL success, NSError *replyError) {
            accepted = success;
            dispatch_semaphore_signal(semaphore);
        }];

        dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 120LL * NSEC_PER_SEC);
        if (dispatch_semaphore_wait(semaphore, timeout) != 0) {
            [context invalidate];
            return -3;
        }
        return accepted ? 0 : -1;
    }
}
