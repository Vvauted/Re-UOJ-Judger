/**
 * @file syscall_policy.h
 * @brief Syscall 策略定义
 * 
 * 将 syscall 限制从硬编码改为插件化配置
 */

#ifndef UOJ_CORE_SYSCALL_POLICY_H
#define UOJ_CORE_SYSCALL_POLICY_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <sys/syscall.h>

namespace uoj {

/**
 * @brief Syscall 限制类型
 */
enum class SyscallLimit {
    FORBIDDEN = 0,      ///< 禁止调用
    UNLIMITED = -1,     ///< 无限制
    // 正整数表示最大调用次数
};

/**
 * @brief 文件权限类型
 */
enum class FilePermission {
    NONE,       ///< 无权限
    STAT,       ///< 只能 stat
    READ,       ///< 可读
    WRITE       ///< 可写（包含读权限）
};

/**
 * @brief Syscall 策略配置
 * 
 * 定义语言运行时需要的系统调用和文件权限
 */
struct SyscallPolicy {
    //==========================================================================
    // Syscall 限制
    //==========================================================================
    
    /// Syscall 调用次数限制 (syscall_number -> max_count, -1 = unlimited)
    std::map<int, int> syscall_limits;
    
    /// 软禁止的 syscall（返回 EACCES 而不是终止程序）
    std::set<int> soft_banned_syscalls;
    
    //==========================================================================
    // 文件权限
    //==========================================================================
    
    /// 可读文件/目录（以 / 结尾表示目录）
    std::vector<std::string> readable_paths;
    
    /// 可写文件/目录
    std::vector<std::string> writable_paths;
    
    /// 可执行文件/目录（Landlock 用）
    std::vector<std::string> execute_paths;
    
    /// 可 stat 的文件/目录
    std::vector<std::string> statable_paths;
    
    /// 软禁止的文件（访问时返回 EACCES）
    std::vector<std::string> soft_banned_paths;
    
    //==========================================================================
    // 特殊权限标志
    //==========================================================================
    
    bool allow_clone = false;       ///< 允许 clone/fork
    bool allow_exec = false;        ///< 允许 execve
    bool allow_network = false;     ///< 允许网络操作
    bool allow_ipc = false;         ///< 允许进程间通信
    bool use_namespace = false;     ///< 启用 namespace 隔离（网络/IPC 等）
    bool use_landlock = true;       ///< 启用 Landlock 限制（默认启用）
    bool use_ptrace = false;        ///< 启用 ptrace TRACE 限制 execve（与 Landlock 二选一）
    
    int max_processes = 1;          ///< 最大进程/线程数（0 = 不限制，默认 1）
    int stack_limit_mb = 8;         ///< 栈大小限制（MB，默认 8）
    bool disable_address_limit = false;  ///< 禁用地址空间限制（JVM 等需要）
    
    //==========================================================================
    // 便捷方法
    //==========================================================================
    
    /// 允许一个 syscall（无限次）
    SyscallPolicy& allow(int syscall_nr) {
        syscall_limits[syscall_nr] = -1;
        return *this;
    }
    
    /// 允许一个 syscall（指定次数）
    SyscallPolicy& allow(int syscall_nr, int max_count) {
        syscall_limits[syscall_nr] = max_count;
        return *this;
    }
    
    /// 软禁止一个 syscall
    SyscallPolicy& soft_ban(int syscall_nr) {
        soft_banned_syscalls.insert(syscall_nr);
        return *this;
    }
    
    /// 添加可读路径
    SyscallPolicy& read(const std::string& path) {
        readable_paths.push_back(path);
        return *this;
    }
    
    /// 添加可写路径
    SyscallPolicy& write(const std::string& path) {
        writable_paths.push_back(path);
        return *this;
    }
    
    /// 添加可 stat 路径
    SyscallPolicy& stat(const std::string& path) {
        statable_paths.push_back(path);
        return *this;
    }
    
    /// 合并另一个策略（添加权限，不会减少）
    SyscallPolicy& merge(const SyscallPolicy& other) {
        for (const auto& [nr, limit] : other.syscall_limits) {
            auto it = syscall_limits.find(nr);
            if (it == syscall_limits.end() || limit == -1 || 
                (it->second != -1 && limit > it->second)) {
                syscall_limits[nr] = limit;
            }
        }
        for (int nr : other.soft_banned_syscalls) {
            soft_banned_syscalls.insert(nr);
        }
        for (const auto& p : other.readable_paths) readable_paths.push_back(p);
        for (const auto& p : other.writable_paths) writable_paths.push_back(p);
        for (const auto& p : other.statable_paths) statable_paths.push_back(p);
        for (const auto& p : other.soft_banned_paths) soft_banned_paths.push_back(p);
        
        allow_clone = allow_clone || other.allow_clone;
        allow_exec = allow_exec || other.allow_exec;
        allow_network = allow_network || other.allow_network;
        allow_ipc = allow_ipc || other.allow_ipc;
        
        return *this;
    }
};

/**
 * @brief 获取基础 syscall 策略（所有语言共享）
 */
inline SyscallPolicy get_base_syscall_policy() {
    SyscallPolicy policy;
    
    // 文件 I/O
    policy.allow(__NR_read)
          .allow(__NR_write)
          .allow(__NR_readv)
          .allow(__NR_writev)
          .allow(__NR_pread64)
          .allow(__NR_open)
          .allow(__NR_close)
          .allow(__NR_openat)
          .allow(__NR_unlink)
          .allow(__NR_unlinkat)
          .allow(__NR_readlink)
          .allow(__NR_readlinkat)
          .allow(__NR_stat)
          .allow(__NR_fstat)
          .allow(__NR_lstat)
          .allow(__NR_lseek)
          .allow(__NR_access)
          .allow(__NR_dup)
          .allow(__NR_dup2)
          .allow(__NR_dup3)
          .allow(__NR_ioctl)
          .allow(__NR_fcntl);
    
    // 内存管理
    policy.allow(__NR_mmap)
          .allow(__NR_mprotect)
          .allow(__NR_munmap)
          .allow(__NR_brk)
          .allow(__NR_mremap)
          .allow(__NR_msync)
          .allow(__NR_mincore)
          .allow(__NR_madvise);
    
    // 信号处理
    policy.allow(__NR_rt_sigaction)
          .allow(__NR_rt_sigprocmask)
          .allow(__NR_rt_sigreturn)
          .allow(__NR_rt_sigpending)
          .allow(__NR_sigaltstack);
    
    // 进程控制
    policy.allow(__NR_exit)
          .allow(__NR_exit_group);
    
    // 系统信息
    policy.allow(__NR_arch_prctl)
          .allow(__NR_getcwd)
          .allow(__NR_gettimeofday)
          .allow(__NR_getrlimit)
          .allow(__NR_getrusage)
          .allow(__NR_times)
          .allow(__NR_time)
          .allow(__NR_clock_gettime)
          .allow(__NR_restart_syscall);
    
    // 基础可读文件
    policy.read("/etc/ld.so.nohwcap")
          .read("/etc/ld.so.preload")
          .read("/etc/ld.so.cache")
          .read("/lib/x86_64-linux-gnu/")
          .read("/usr/lib/x86_64-linux-gnu/")
          .read("/usr/lib/locale/locale-archive")
          .read("/proc/self/exe")
          .read("/etc/timezone")
          .read("/usr/share/zoneinfo/")
          .read("/dev/random")
          .read("/dev/urandom")
          .read("/proc/meminfo")
          .read("/etc/localtime");
    
    return policy;
}

/**
 * @brief 获取编译器 syscall 策略（所有编译器共享的基础）
 */
inline SyscallPolicy get_compiler_base_policy() {
    SyscallPolicy policy = get_base_syscall_policy();
    
    // 进程管理
    policy.allow(__NR_getpid)
          .allow(__NR_gettid)
          .allow(__NR_set_tid_address)
          .allow(__NR_set_robust_list)
          .allow(__NR_futex)
          .allow(__NR_vfork)
          .allow(__NR_fork)
          .allow(__NR_clone)
          .allow(__NR_execve)
          .allow(__NR_wait4);
    
    policy.allow_clone = true;
    policy.allow_exec = true;
    
    // 时间
    policy.allow(__NR_clock_gettime)
          .allow(__NR_clock_getres);
    
    // 资源限制
    policy.allow(__NR_setrlimit)
          .allow(__NR_prlimit64);
    
    // 管道
    policy.allow(__NR_pipe)
          .allow(__NR_pipe2);
    
    // 目录操作
    policy.allow(__NR_getdents)
          .allow(__NR_getdents64)
          .allow(__NR_chdir)
          .allow(__NR_fchdir);
    
    // 文件操作
    policy.allow(__NR_umask)
          .allow(__NR_rename)
          .allow(__NR_chmod)
          .allow(__NR_mkdir)
          .allow(__NR_ftruncate);
    
    // 调度
    policy.allow(__NR_sched_getaffinity)
          .allow(__NR_sched_yield);
    
    // 系统信息
    policy.allow(__NR_uname)
          .allow(__NR_sysinfo)
          .allow(__NR_getrandom)
          .allow(__NR_pread64)
          .allow(__NR_prctl)
          .allow(__NR_nanosleep)
          .allow(__NR_clock_nanosleep)
          .allow(__NR_socketpair);
    
    // Java 编译需要的软禁止
    policy.soft_ban(__NR_socket)
          .soft_ban(__NR_connect)
          .soft_ban(__NR_geteuid)
          .soft_ban(__NR_getuid);
    
    // 文件权限
    policy.write("/tmp/")
          .read("/usr/")
          .read("/lib/")
          .read("/lib64/")
          .read("/bin/")
          .read("/sbin/")
          .read("/proc/")
          .read("/sys/devices/system/cpu/")
          .read("/sys/fs/cgroup/cpu/")
          .read("/sys/fs/cgroup/cpu,cpuacct/")
          .read("/sys/fs/cgroup/memory/")
          .read("/etc/timezone")
          .read("/etc/fpc.cfg");
    
    policy.soft_banned_paths.push_back("/etc/nsswitch.conf");
    policy.soft_banned_paths.push_back("/etc/passwd");
    
    return policy;
}

} // namespace uoj

#endif // UOJ_CORE_SYSCALL_POLICY_H

