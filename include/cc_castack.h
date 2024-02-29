#ifndef _CC_CC_CASTACK_H_
#define _CC_CC_CASTACK_H_

#include "cc.h"

#include <stdlib.h>
#include <sys/resource.h>

#ifdef CC_CA_STACK_ENABLE

static inline int cc_call_main_with_castack(const uint64_t stack_end,
                                            int (*main)(int, char **, char **),
                                            int argc, char **argv,
                                            char **envp) {
    if (getenv("CASTACK_ENABLED") == NULL) {
        // Only encrypt stack if CASTACK_ENABLED is set.
        return main(argc, argv, envp);
    }

    struct rlimit limit;
    getrlimit(RLIMIT_STACK, &limit);
    const uint64_t size = (uint64_t)limit.rlim_cur;

    uint64_t rsp;
    asm volatile("mov %%rsp, %0;\n" : "=r"(rsp) : :);

    const uint64_t offset = rsp - (stack_end - size);

    rsp = cc_isa_encptr_sv((rsp - offset), (size), 0) + offset;

    if (!rsp) {
        // Failed to encrypt %rsp so just directly call main
        return main(argc, argv, envp);
    }

    // Everything seems a'okay, swap %rsp and call main
    asm volatile("mov %%rcx, %%rsp;   \n"
                 "call *%%rax;        \n"
                 "mov %%rsp, %%rdx;   \n"
                 ".byte 0xf0          \n" /* decptr %rsp*/
                 ".byte 0x48          \n" /* ... */
                 ".byte 0x01          \n" /* ... */
                 ".byte 0xd2;         \n" /* ... */
                 "mov %%rdx, %%rsp;   \n"
                 : "+a"((main)) /* main pointer AND result */
                 : "D"((argc)), "S"((argv)), "d"((envp)), "c"(rsp)
                 : "memory", "rbx", "rbp", "r8", "r9", "r10", "r11", "r12",
                   "r13", "r14", "r15");
    return (uint64_t)main;
}

#endif  // CC_ENABLE_CA_STACK
#endif  // _CC_CC_CASTACK_H_