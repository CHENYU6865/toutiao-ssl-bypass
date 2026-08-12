#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <fishhook/fishhook.h>

#pragma mark - 日志
#define HBLog(fmt, ...) NSLog(@"[SSLBypass] " fmt, ##__VA_ARGS__)

#pragma mark - 原始函数指针
static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
static Boolean (*orig_SecTrustEvaluateWithError)(SecTrustRef trust, CFErrorRef *error);
static OSStatus (*orig_SecTrustGetTrustResult)(SecTrustRef trust, SecTrustResultType *result);

#pragma mark - Hook 实现

// 旧版 SecTrustEvaluate：直接返回信任
OSStatus hook_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    HBLog(@"SecTrustEvaluate hooked -> proceed");
    return errSecSuccess;
}

// 新版 SecTrustEvaluateWithError (iOS 13+)：直接返回 true，无错误
Boolean hook_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    if (error) *error = NULL;
    HBLog(@"SecTrustEvaluateWithError hooked -> true");
    return true;
}

// SecTrustGetTrustResult：始终返回 proceed
OSStatus hook_SecTrustGetTrustResult(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    HBLog(@"SecTrustGetTrustResult hooked -> proceed");
    return errSecSuccess;
}

#pragma mark - NSURLSessionDelegate Hook

// 处理 NSURLSession 的证书校验 challenge
static void (*orig_URLSession_didReceiveChallenge_completionHandler)(id self, SEL _cmd, NSURLSession *session, NSURLAuthenticationChallenge *challenge, void (^completionHandler)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential));

void hook_URLSession_didReceiveChallenge_completionHandler(id self, SEL _cmd, NSURLSession *session, NSURLAuthenticationChallenge *challenge, void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential *)) {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        HBLog(@"NSURLSession server trust challenge -> use credential");
        NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        return;
    }
    orig_URLSession_didReceiveChallenge_completionHandler(self, _cmd, session, challenge, completionHandler);
}

#pragma mark - 对所有实现了 didReceiveChallenge 的类进行 Method Swizzle

static void swizzleURLSessionDelegate(void) {
    int numClasses = objc_getClassList(NULL, 0);
    if (numClasses <= 0) return;

    Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * numClasses);
    numClasses = objc_getClassList(classes, numClasses);

    SEL challengeSEL = @selector(URLSession:didReceiveChallenge:completionHandler:);

    for (int i = 0; i < numClasses; i++) {
        Class cls = classes[i];
        if (!cls) continue;

        // 只扫当前类自身的方法，不递归父类
        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(cls, &methodCount);
        if (!methods) continue;

        for (unsigned int j = 0; j < methodCount; j++) {
            SEL methodSEL = method_getName(methods[j]);
            if (methodSEL == challengeSEL) {
                IMP origIMP = method_getImplementation(methods[j]);
                IMP hookIMP = (IMP)hook_URLSession_didReceiveChallenge_completionHandler;

                method_setImplementation(methods[j], hookIMP);
                orig_URLSession_didReceiveChallenge_completionHandler = (void *)origIMP;

                HBLog(@"Swizzled %@", NSStringFromClass(cls));
                break;
            }
        }
        free(methods);
    }
    free(classes);
}

#pragma mark - 构造函数：进程启动时自动执行

__attribute__((constructor))
static void SSLBypassInit(void) {
    @autoreleasepool {
        HBLog(@"=== SSL Pinning Bypass loaded ===");

        // 1. fishhook 系统 Security 框架函数
        struct rebinding rebindings[] = {
            {"SecTrustEvaluate", (void *)hook_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate},
            {"SecTrustEvaluateWithError", (void *)hook_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError},
            {"SecTrustGetTrustResult", (void *)hook_SecTrustGetTrustResult, (void **)&orig_SecTrustGetTrustResult},
        };
        rebind_symbols(rebindings, sizeof(rebindings) / sizeof(struct rebinding));
        HBLog(@"fishhook Security functions done");

        // 2. 延迟 swizzle NSURLSession delegate（等类加载完）
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            swizzleURLSessionDelegate();
            HBLog(@"NSURLSession delegate swizzle done");
        });

        HBLog(@"=== SSL Pinning Bypass init complete ===");
    }
}
