// 轻量版 SSL Pinning Bypass dylib
// 不内嵌 fishhook，只 swizzle NSURLSession delegate，避免 iOS 15 __DATA_CONST 写保护崩溃

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

#define HBLog(fmt, ...) NSLog(@"[SSLBypass] " fmt, ##__VA_ARGS__)

static void (*orig_didReceiveChallenge)(id self, SEL _cmd, NSURLSession *session, NSURLAuthenticationChallenge *challenge, void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential *));

static void hook_didReceiveChallenge(id self, SEL _cmd, NSURLSession *session, NSURLAuthenticationChallenge *challenge, void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential *)) {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        NSURLCredential *cred = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        completionHandler(NSURLSessionAuthChallengeUseCredential, cred);
        return;
    }
    if (orig_didReceiveChallenge) {
        orig_didReceiveChallenge(self, _cmd, session, challenge, completionHandler);
    } else {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

static void swizzleAllURLSessionDelegates(void) {
    int numClasses = objc_getClassList(NULL, 0);
    if (numClasses <= 0) return;
    Class *classes = (Class *)malloc(sizeof(Class) * numClasses);
    numClasses = objc_getClassList(classes, numClasses);
    SEL sel = @selector(URLSession:didReceiveChallenge:completionHandler:);

    for (int i = 0; i < numClasses; i++) {
        Class cls = classes[i];
        if (!cls) continue;

        // 跳过系统类，避免误改系统行为
        const char *clsName = class_getName(cls);
        if (strncmp(clsName, "NS", 2) == 0 ||
            strncmp(clsName, "UI", 2) == 0 ||
            strncmp(clsName, "_", 1) == 0 ||
            strstr(clsName, "Foundation") != NULL ||
            strstr(clsName, "CFNetwork") != NULL) {
            continue;
        }

        unsigned int count = 0;
        Method *methods = class_copyMethodList(cls, &count);
        if (!methods) continue;
        for (unsigned int j = 0; j < count; j++) {
            if (method_getName(methods[j]) == sel) {
                IMP orig = method_getImplementation(methods[j]);
                method_setImplementation(methods[j], (IMP)hook_didReceiveChallenge);
                orig_didReceiveChallenge = (void *)orig;
                HBLog(@"Swizzled delegate: %s", clsName);
                break;
            }
        }
        free(methods);
    }
    free(classes);
}

__attribute__((constructor))
static void SSLBypassInit(void) {
    @autoreleasepool {
        HBLog(@"loaded");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            swizzleAllURLSessionDelegates();
            HBLog(@"init complete");
        });
    }
}
