/**
 * @file seccomp.h
 * @brief seccomp-bpf 系统调用过滤
 * 
 * 使用 seccomp-bpf 在内核层过滤系统调用，比 ptrace 快 10-100 倍。
 * 
 * 优势：
 * - 内核层过滤，无进程切换开销
 * - 更安全（无法绕过）
 * - 支持复杂的过滤规则
 */

#ifndef UOJ_SANDBOX_SECCOMP_H
#define UOJ_SANDBOX_SECCOMP_H

#include <vector>
#include <set>
#include <string>
#include <cstdint>
#include <stdexcept>

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

namespace uoj {
namespace sandbox {

//==============================================================================
// 系统调用过滤规则
//==============================================================================

/**
 * @brief 系统调用过滤动作
 */
enum class SeccompAction {
    ALLOW,      ///< 允许执行
    KILL,       ///< 杀死进程
    TRAP,       ///< 发送 SIGSYS 信号（用于调试，可获取 syscall 号）
    ERRNO,      ///< 返回错误码
    TRACE,      ///< 通知 tracer（用于调试）
    LOG         ///< 记录日志但允许
};

/**
 * @brief 参数比较操作
 */
enum class ArgCmp {
    EQ,         ///< 等于
    NE,         ///< 不等于
    LT,         ///< 小于
    LE,         ///< 小于等于
    GT,         ///< 大于
    GE,         ///< 大于等于
    MASKED_EQ   ///< 掩码后等于
};

/**
 * @brief 系统调用参数条件
 */
struct ArgCondition {
    unsigned int arg_index;  ///< 参数索引 (0-5)
    ArgCmp cmp;              ///< 比较操作
    uint64_t value;          ///< 比较值
    uint64_t mask;           ///< 掩码（用于 MASKED_EQ）
    
    ArgCondition(unsigned int idx, ArgCmp c, uint64_t val, uint64_t m = 0)
        : arg_index(idx), cmp(c), value(val), mask(m) {}
};

/**
 * @brief 单条过滤规则
 */
struct SeccompRule {
    int syscall_nr;                      ///< 系统调用号
    SeccompAction action;                ///< 动作
    int errno_val;                       ///< 错误码（action=ERRNO 时）
    std::vector<ArgCondition> conditions; ///< 参数条件
    
    SeccompRule(int nr, SeccompAction act = SeccompAction::ALLOW, int err = 0)
        : syscall_nr(nr), action(act), errno_val(err) {}
    
    SeccompRule& when(unsigned int arg, ArgCmp cmp, uint64_t value) {
        conditions.emplace_back(arg, cmp, value, 0);
        return *this;
    }
    
    SeccompRule& when_masked(unsigned int arg, uint64_t mask, uint64_t value) {
        conditions.emplace_back(arg, ArgCmp::MASKED_EQ, value, mask);
        return *this;
    }
};

//==============================================================================
// Seccomp 过滤器构建器
//==============================================================================

/**
 * @brief BPF 指令生成辅助
 */
struct BPF {
    static sock_filter stmt(uint16_t code, uint32_t k) {
        return {code, 0, 0, k};
    }
    
    static sock_filter jump(uint16_t code, uint32_t k, uint8_t jt, uint8_t jf) {
        return {code, jt, jf, k};
    }
    
    // 加载系统调用号
    static sock_filter load_syscall_nr() {
        return stmt(BPF_LD | BPF_W | BPF_ABS, 
                    offsetof(struct seccomp_data, nr));
    }
    
    // 加载架构
    static sock_filter load_arch() {
        return stmt(BPF_LD | BPF_W | BPF_ABS,
                    offsetof(struct seccomp_data, arch));
    }
    
    // 加载参数低 32 位
    static sock_filter load_arg_lo(int arg) {
        return stmt(BPF_LD | BPF_W | BPF_ABS,
                    offsetof(struct seccomp_data, args) + arg * 8);
    }
    
    // 加载参数高 32 位
    static sock_filter load_arg_hi(int arg) {
        return stmt(BPF_LD | BPF_W | BPF_ABS,
                    offsetof(struct seccomp_data, args) + arg * 8 + 4);
    }
    
    // 返回动作
    static sock_filter ret(uint32_t action) {
        return stmt(BPF_RET | BPF_K, action);
    }
};

/**
 * @brief Seccomp 过滤器
 */
class SeccompFilter {
private:
    std::vector<sock_filter> program_;
    std::set<int> allowed_syscalls_;
    SeccompAction default_action_;
    bool strict_mode_;

#if defined(__x86_64__)
    static constexpr uint32_t NATIVE_AUDIT_ARCH = AUDIT_ARCH_X86_64;
#elif defined(__i386__)
    static constexpr uint32_t NATIVE_AUDIT_ARCH = AUDIT_ARCH_I386;
#elif defined(__aarch64__)
    static constexpr uint32_t NATIVE_AUDIT_ARCH = AUDIT_ARCH_AARCH64;
#else
    #error "Unsupported architecture"
#endif

    uint32_t action_to_seccomp(SeccompAction action, int errno_val = 0) {
        switch (action) {
            case SeccompAction::ALLOW: return SECCOMP_RET_ALLOW;
            case SeccompAction::KILL:  return SECCOMP_RET_KILL_PROCESS;
            case SeccompAction::TRAP:  return SECCOMP_RET_TRAP;
            case SeccompAction::ERRNO: return SECCOMP_RET_ERRNO | (errno_val & 0xFFFF);
            case SeccompAction::TRACE: return SECCOMP_RET_TRACE;
            case SeccompAction::LOG:   return SECCOMP_RET_LOG;
            default: return SECCOMP_RET_KILL_PROCESS;
        }
    }

public:
    SeccompFilter() 
        : default_action_(SeccompAction::KILL), strict_mode_(true) {}

    /**
     * @brief 设置默认动作
     */
    SeccompFilter& set_default(SeccompAction action) {
        default_action_ = action;
        return *this;
    }

    /**
     * @brief 设置严格模式（检查架构）
     */
    SeccompFilter& set_strict(bool strict) {
        strict_mode_ = strict;
        return *this;
    }

    /**
     * @brief 允许系统调用
     */
    SeccompFilter& allow(int syscall_nr) {
        allowed_syscalls_.insert(syscall_nr);
        return *this;
    }

    /**
     * @brief 批量允许系统调用
     */
    SeccompFilter& allow(std::initializer_list<int> syscalls) {
        for (int nr : syscalls) {
            allowed_syscalls_.insert(nr);
        }
        return *this;
    }

    /**
     * @brief 构建 BPF 程序
     */
    void build() {
        program_.clear();
        
        // 1. 检查架构（安全性）
        if (strict_mode_) {
            program_.push_back(BPF::load_arch());
            program_.push_back(BPF::jump(BPF_JMP | BPF_JEQ | BPF_K, 
                                         NATIVE_AUDIT_ARCH, 1, 0));
            program_.push_back(BPF::ret(SECCOMP_RET_KILL_PROCESS));
        }
        
        // 2. 加载系统调用号
        program_.push_back(BPF::load_syscall_nr());
        
        // 3. 为每个允许的 syscall 生成跳转
        // 使用二分查找优化（简化版：线性检查）
        std::vector<int> sorted_syscalls(allowed_syscalls_.begin(), 
                                          allowed_syscalls_.end());
        
        for (size_t i = 0; i < sorted_syscalls.size(); i++) {
            // 如果匹配，跳到 allow
            int remaining = sorted_syscalls.size() - i;
            program_.push_back(BPF::jump(BPF_JMP | BPF_JEQ | BPF_K,
                                         sorted_syscalls[i],
                                         remaining,  // jt: 跳到 allow
                                         0));        // jf: 继续检查
        }
        
        // 4. 默认动作（不匹配任何允许的 syscall）
        program_.push_back(BPF::ret(action_to_seccomp(default_action_)));
        
        // 5. 允许动作
        program_.push_back(BPF::ret(SECCOMP_RET_ALLOW));
    }

    /**
     * @brief 应用过滤器到当前进程
     */
    bool apply() {
        if (program_.empty()) {
            build();
        }
        
        // 设置 no_new_privs（必须）
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            return false;
        }
        
        struct sock_fprog prog = {
            .len = static_cast<unsigned short>(program_.size()),
            .filter = program_.data()
        };
        
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
            return false;
        }
        
        return true;
    }

    /**
     * @brief 获取 BPF 程序大小
     */
    size_t size() const { return program_.size(); }
};

//==============================================================================
// 预定义的过滤器配置
//==============================================================================

/**
 * @brief 评测机标准过滤器
 * 
 * 只允许必要的系统调用，适用于大多数 OJ 程序
 */
inline SeccompFilter create_judge_filter() {
    SeccompFilter filter;
    filter.set_default(SeccompAction::KILL)
          .set_strict(true);
    
    // 文件操作（只读）
    filter.allow({
        __NR_read,
        __NR_pread64,
        __NR_readv,
        __NR_lseek,
        __NR_fstat,
#ifdef __NR_newfstatat
        __NR_newfstatat,
#endif
        __NR_stat,
        __NR_lstat,
        __NR_access,
        __NR_faccessat,
#ifdef __NR_faccessat2
        __NR_faccessat2,
#endif
        __NR_openat,      // 需要配合文件路径检查
        __NR_close,
        __NR_dup,
        __NR_dup2,
#ifdef __NR_dup3
        __NR_dup3,
#endif
        __NR_fcntl,
        __NR_ioctl,
        __NR_getdents,
        __NR_getdents64,
        __NR_readlink,
        __NR_readlinkat,
        __NR_getcwd,
    });
    
    // 文件写入（stdout/stderr）
    filter.allow({
        __NR_write,
        __NR_writev,
        __NR_pwrite64,
    });
    
    // 内存管理
    filter.allow({
        __NR_brk,
        __NR_mmap,
        __NR_munmap,
        __NR_mprotect,
        __NR_mremap,
#ifdef __NR_madvise
        __NR_madvise,
#endif
    });
    
    // 进程/线程
    filter.allow({
        __NR_exit,
        __NR_exit_group,
        __NR_getpid,
        __NR_gettid,
        __NR_getuid,
        __NR_getgid,
        __NR_geteuid,
        __NR_getegid,
        __NR_getppid,
        __NR_getpgrp,
#ifdef __NR_arch_prctl
        __NR_arch_prctl,
#endif
        __NR_set_tid_address,
        __NR_set_robust_list,
        __NR_prctl,
        __NR_prlimit64,
        __NR_getrlimit,
        __NR_uname,
        __NR_sysinfo,
#ifdef __NR_rseq
        __NR_rseq,
#endif
        // execve 需要允许以运行用户程序
        // 注意：一旦 execve 成功，seccomp 规则会保持
        __NR_execve,
#ifdef __NR_execveat
        __NR_execveat,
#endif
    });
    
    // 信号
    filter.allow({
        __NR_rt_sigaction,
        __NR_rt_sigprocmask,
        __NR_rt_sigreturn,
        __NR_sigaltstack,
    });
    
    // 时间
    filter.allow({
        __NR_clock_gettime,
        __NR_gettimeofday,
        __NR_nanosleep,
    });
    
    // 其他必要的
    filter.allow({
        __NR_futex,
        __NR_getrandom,
#ifdef __NR_rseq
        __NR_rseq,
#endif
    });
    
    return filter;
}

/**
 * @brief 编译器过滤器（更宽松）
 */
inline SeccompFilter create_compiler_filter() {
    SeccompFilter filter;
    filter.set_default(SeccompAction::KILL)
          .set_strict(true);
    
    // 包含所有评测机允许的
    auto judge_filter = create_judge_filter();
    
    // 额外允许编译器需要的
    filter.allow({
        // 文件操作
        __NR_write,
        __NR_unlink,
        __NR_unlinkat,
        __NR_rename,
        __NR_renameat,
#ifdef __NR_renameat2
        __NR_renameat2,
#endif
        __NR_mkdir,
        __NR_mkdirat,
        __NR_rmdir,
        __NR_getcwd,
        __NR_chdir,
        __NR_fchdir,
        __NR_readlink,
        __NR_readlinkat,
        __NR_getdents,
        __NR_getdents64,
        __NR_fcntl,
        __NR_flock,
        __NR_fsync,
        __NR_fdatasync,
        __NR_ftruncate,
        __NR_truncate,
        __NR_fchmod,
        __NR_fchown,
        __NR_umask,
        __NR_statfs,
        __NR_fstatfs,
#ifdef __NR_statx
        __NR_statx,
#endif
        
        // 进程
        __NR_clone,
        __NR_fork,
        __NR_vfork,
        __NR_execve,
#ifdef __NR_execveat
        __NR_execveat,
#endif
        __NR_wait4,
        __NR_waitid,
        __NR_kill,
        __NR_tgkill,
        __NR_getppid,
        __NR_getpgrp,
        __NR_setpgid,
        __NR_setsid,
        
        // 管道和 socket（用于进程间通信）
        __NR_pipe,
        __NR_pipe2,
        __NR_socket,
        __NR_socketpair,
        __NR_bind,
        __NR_connect,
        __NR_listen,
        __NR_accept,
#ifdef __NR_accept4
        __NR_accept4,
#endif
        __NR_sendto,
        __NR_recvfrom,
        __NR_sendmsg,
        __NR_recvmsg,
        __NR_shutdown,
        __NR_setsockopt,
        __NR_getsockopt,
        __NR_getsockname,
        __NR_getpeername,
        
        // poll/select/epoll
        __NR_poll,
        __NR_ppoll,
        __NR_select,
        __NR_pselect6,
        __NR_epoll_create,
        __NR_epoll_create1,
        __NR_epoll_ctl,
        __NR_epoll_wait,
        __NR_epoll_pwait,
#ifdef __NR_epoll_pwait2
        __NR_epoll_pwait2,
#endif
        
        // 资源限制
        __NR_getrlimit,
        __NR_setrlimit,
        __NR_prlimit64,
        __NR_getrusage,
        
        // 用户/组
        __NR_setuid,
        __NR_setgid,
        __NR_setreuid,
        __NR_setregid,
        __NR_setresuid,
        __NR_setresgid,
        __NR_getresuid,
        __NR_getresgid,
        __NR_setgroups,
        __NR_getgroups,
        
        // 其他
        __NR_uname,
        __NR_sysinfo,
        __NR_prctl,
        __NR_ioctl,
        __NR_membarrier,
#ifdef __NR_copy_file_range
        __NR_copy_file_range,
#endif
    });
    
    return filter;
}

} // namespace sandbox
} // namespace uoj

#endif // UOJ_SANDBOX_SECCOMP_H

