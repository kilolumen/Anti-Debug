//
//  main.m
//  AntiDebug
//
//  Created by lidongjie on 2018/8/28.
//  Copyright © 2018年 kilolumen. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"

#import <dlfcn.h>
#import <sys/types.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>

// ptrace
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
static void anti_debug_01() {
    void *handle = dlopen(NULL, RTLD_GLOBAL | RTLD_NOW);
    ptrace_ptr_t ptrace_ptr = dlsym(handle, "ptrace");
    ptrace_ptr(PT_DENY_ATTACH, 0, 0, 0);
    dlclose(handle);
}

// svc + ptrace
static __attribute__((always_inline)) void anti_debug_02() {
#ifdef __arm64__
    __asm__("mov X0, #31\n"
            "mov X1, #0\n"
            "mov X2, #0\n"
            "mov X3, #0\n"
            "mov w16, #26\n"
            "svc #0x80");
#endif
}

// svc + syscall + ptrace
static __attribute__((always_inline)) void anti_debug_03() {
#ifdef __arm64__
    __asm__("mov X0, #26\n"
            "mov X1, #31\n"
            "mov X2, #0\n"
            "mov X3, #0\n"
            "mov X4, #0\n"
            "mov w16, #0\n"
            "svc #0x80");
#endif
}

// syscall
static void anti_debug_04() {
    syscall(SYS_ptrace, PT_DENY_ATTACH, 0, 0, 0);
}

// sysctl
static __attribute__((always_inline)) void anti_debug_05() {
    struct kinfo_proc Kproc;
    size_t kproc_size = sizeof(Kproc);
    int name[4];
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    
    memset((void *)&Kproc, 0, kproc_size);
    if (sysctl(name, 4, &Kproc, &kproc_size, NULL, 0) == -1) {
        exit(-1);
    }
    
    if (Kproc.kp_proc.p_flag & P_TRACED) {
        exit(-1);
    }
}

int main(int argc, char * argv[]) {
    
    // 反调试
#ifndef DEBUG
    anti_debug_01();
    anti_debug_02();
    anti_debug_03();
    anti_debug_04();
    anti_debug_05();
#endif
    
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
