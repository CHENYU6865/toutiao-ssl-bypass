// 独立版 SSL Pinning Bypass dylib
// 内嵌 fishhook，无需额外依赖，可直接用 clang 编译
// 编译命令见底部注释

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <sys/mman.h>
#import <string.h>
#import <stdlib.h>

#pragma mark - ===== 内嵌 fishhook 实现 =====

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST "__DATA_CONST"
#endif


#if defined(__LP64__)
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif


struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

struct rebindings_entry {
    struct rebinding *rebindings;
    size_t rebindings_nel;
    struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static int prepend_rebindings(struct rebindings_entry **rebindings_head, struct rebinding rebindings[], size_t nel) {
    struct rebindings_entry *new_entry = (struct rebindings_entry *)malloc(sizeof(struct rebindings_entry));
    if (!new_entry) return -1;
    new_entry->rebindings = (struct rebinding *)malloc(sizeof(struct rebinding) * nel);
    if (!new_entry->rebindings) { free(new_entry); return -1; }
    memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
    new_entry->rebindings_nel = nel;
    new_entry->next = *rebindings_head;
    *rebindings_head = new_entry;
    return 0;
}

static void perform_rebinding_with_section(struct rebindings_entry *rebindings, section_t *section, intptr_t slide, nlist_t *symtab, char *strtab, uint32_t *indirect_symtab) {
    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    if (!indirect_symbol_bindings || section->size == 0) return;

    uintptr_t section_start = (uintptr_t)indirect_symbol_bindings;
    uintptr_t section_end = section_start + section->size;
    uintptr_t page_size = getpagesize();
    uintptr_t start_page = section_start & ~(page_size - 1);
    uintptr_t end_page = (section_end + page_size - 1) & ~(page_size - 1);
    mprotect((void *)start_page, end_page - start_page, PROT_READ | PROT_WRITE);

    for (uint i = 0; i < section->size / sizeof(void *); i++) {
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL || symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) continue;
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        char *symbol_name = strtab + strtab_offset;
        if (strnlen(symbol_name, 512) < 2) continue;
        struct rebindings_entry *cur = rebindings;
        while (cur) {
            for (uint j = 0; j < cur->rebindings_nel; j++) {
                if (strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    if (cur->rebindings[j].replaced != NULL && indirect_symbol_bindings[i] != cur->rebindings[j].replacement)
                        *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
                    indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
                    goto symbol_loop;
                }
            }
            cur = cur->next;
        }
    symbol_loop:;
    }

    mprotect((void *)start_page, end_page - start_page, PROT_READ);
}

static void rebind_symbols_for_image(struct rebindings_entry *rebindings, const mach_header_t *header, intptr_t slide) {
    Dl_info info;
    if (dladdr(header, &info) == 0) return;
    segment_command_t *cur_seg_cmd;
    segment_command_t *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (segment_command_t *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) linkedit_segment = cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
        }
    }
    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment || !dysymtab_cmd->nindirectsyms) return;

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (segment_command_t *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
            if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 && strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) continue;
            for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
                section_t *sect = (section_t *)(cur + sizeof(segment_command_t)) + j;
                if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS || (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS)
                    perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
            }
        }
    }
}

static void _rebind_symbols_for_image(const struct mach_header *header, intptr_t slide) {
    rebind_symbols_for_image(_rebindings_head, (const mach_header_t *)header, slide);
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
    int retval = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
    if (retval < 0) return retval;
    if (!_rebindings_head->next) _dyld_register_func_for_add_image(_rebind_symbols_for_image);
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    return retval;
}

#pragma mark - ===== SSL Bypass 主体 =====

#define HBLog(fmt, ...) NSLog(@"[SSLBypass] " fmt, ##__VA_ARGS__)

static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
static Boolean (*orig_SecTrustEvaluateWithError)(SecTrustRef trust, CFErrorRef *error);
static OSStatus (*orig_SecTrustGetTrustResult)(SecTrustRef trust, SecTrustResultType *result);

OSStatus hook_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}

Boolean hook_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    if (error) *error = NULL;
    return true;
}

OSStatus hook_SecTrustGetTrustResult(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}

// NSURLSession challenge hook
static void (*orig_didReceiveChallenge)(id self, SEL _cmd, NSURLSession *session, NSURLAuthenticationChallenge *challenge, void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential *));

void hook_didReceiveChallenge(id self, SEL _cmd, NSURLSession *session, NSURLAuthenticationChallenge *challenge, void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential *)) {
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        NSURLCredential *cred = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
        completionHandler(NSURLSessionAuthChallengeUseCredential, cred);
        return;
    }
    if (orig_didReceiveChallenge) orig_didReceiveChallenge(self, _cmd, session, challenge, completionHandler);
    else completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

static void swizzleAllURLSessionDelegates(void) {
    int numClasses = objc_getClassList(NULL, 0);
    if (numClasses <= 0) return;
    Class *classes = malloc(sizeof(Class) * numClasses);
    numClasses = objc_getClassList(classes, numClasses);
    SEL sel = @selector(URLSession:didReceiveChallenge:completionHandler:);

    for (int i = 0; i < numClasses; i++) {
        unsigned int count = 0;
        Method *methods = class_copyMethodList(classes[i], &count);
        if (!methods) continue;
        for (unsigned int j = 0; j < count; j++) {
            if (method_getName(methods[j]) == sel) {
                IMP orig = method_getImplementation(methods[j]);
                method_setImplementation(methods[j], (IMP)hook_didReceiveChallenge);
                orig_didReceiveChallenge = (void *)orig;
                HBLog(@"Swizzled delegate: %s", class_getName(classes[i]));
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

        struct rebinding r[] = {
            {"SecTrustEvaluate", (void *)hook_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate},
            {"SecTrustEvaluateWithError", (void *)hook_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError},
            {"SecTrustGetTrustResult", (void *)hook_SecTrustGetTrustResult, (void **)&orig_SecTrustGetTrustResult},
        };
        rebind_symbols(r, sizeof(r)/sizeof(struct rebinding));

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            swizzleAllURLSessionDelegates();
            HBLog(@"init complete");
        });
    }
}

/*
 ===== 编译命令（在 Mac 上执行）=====

 # 方式1：直接 clang 编译（推荐，最简单）
 clang -arch arm64 -dynamiclib -o SSLBypass.dylib SSLBypass.m \
   -framework Foundation -framework Security -framework CoreFoundation \
   -miphoneos-version-min=14.0 -isysroot $(xcrun --sdk iphoneos --show-sdk-path)

 # 方式2：用 Theos（如果你有 Theos 环境）
 # 把 SSLBypass.m 放到 Tweak.xm，Makefile 里写：
 # ARCHS = arm64 arm64e
 # TARGET = iphone:clang:16.5:14.0
 # INSTALL_TARGET_PROCESSES = 今日头条
 # 然后 make package

 编译产物：SSLBypass.dylib
 用 TrollFools 注入到「今日头条」即可。
 */
