/**
 * @file syscall_map.h
 * @brief 统一的 syscall 名称到编号映射
 * 
 * 所有需要解析 syscall 名称的地方都应该使用这个文件中的映射，
 * 避免重复定义。
 */

#ifndef UOJ_CORE_SYSCALL_MAP_H
#define UOJ_CORE_SYSCALL_MAP_H

#include <string>
#include <map>
#include <sys/syscall.h>

namespace uoj {

/**
 * @brief Syscall 名称到编号的统一映射
 */
class SyscallMap {
public:
    static SyscallMap& instance() {
        static SyscallMap inst;
        return inst;
    }
    
    /**
     * @brief 将 syscall 名称转换为编号
     * @return syscall 编号，如果未知返回 -1
     */
    int name_to_nr(const std::string& name) const {
        auto it = map_.find(name);
        return it != map_.end() ? it->second : -1;
    }
    
    /**
     * @brief 将 syscall 编号转换为名称
     * @return syscall 名称，如果未知返回空字符串
     */
    std::string nr_to_name(int nr) const {
        for (const auto& [name, num] : map_) {
            if (num == nr) return name;
        }
        return "";
    }
    
private:
    SyscallMap() {
        // 基础 syscall
        map_ = {
            // 文件 I/O
            {"read", __NR_read},
            {"write", __NR_write},
            {"open", __NR_open},
            {"close", __NR_close},
            {"openat", __NR_openat},
            {"stat", __NR_stat},
            {"fstat", __NR_fstat},
            {"lstat", __NR_lstat},
            {"newfstatat", __NR_newfstatat},
            {"statx", __NR_statx},
            {"access", __NR_access},
            {"faccessat", __NR_faccessat},
            {"readlink", __NR_readlink},
            {"readlinkat", __NR_readlinkat},
            {"getdents", __NR_getdents},
            {"getdents64", __NR_getdents64},
            {"lseek", __NR_lseek},
            {"pread64", __NR_pread64},
            {"pwrite64", __NR_pwrite64},
            {"readv", __NR_readv},
            {"writev", __NR_writev},
            {"dup", __NR_dup},
            {"dup2", __NR_dup2},
            {"dup3", __NR_dup3},
            {"pipe", __NR_pipe},
            {"pipe2", __NR_pipe2},
            {"fcntl", __NR_fcntl},
            {"flock", __NR_flock},
            {"fsync", __NR_fsync},
            {"fdatasync", __NR_fdatasync},
            {"ftruncate", __NR_ftruncate},
            {"truncate", __NR_truncate},
            {"rename", __NR_rename},
            {"mkdir", __NR_mkdir},
            {"rmdir", __NR_rmdir},
            {"unlink", __NR_unlink},
            {"unlinkat", __NR_unlinkat},
            {"getcwd", __NR_getcwd},
            {"chdir", __NR_chdir},
            {"fchdir", __NR_fchdir},
            
            // 内存管理
            {"mmap", __NR_mmap},
            {"mprotect", __NR_mprotect},
            {"munmap", __NR_munmap},
            {"brk", __NR_brk},
            {"mremap", __NR_mremap},
            {"madvise", __NR_madvise},
            {"msync", __NR_msync},
            {"mincore", __NR_mincore},
            
            // 进程控制
            {"clone", __NR_clone},
            {"clone3", __NR_clone3},
            {"fork", __NR_fork},
            {"vfork", __NR_vfork},
            {"execve", __NR_execve},
            {"exit", __NR_exit},
            {"exit_group", __NR_exit_group},
            {"wait4", __NR_wait4},
            {"kill", __NR_kill},
            {"tkill", __NR_tkill},
            {"tgkill", __NR_tgkill},
            {"getpid", __NR_getpid},
            {"gettid", __NR_gettid},
            {"getppid", __NR_getppid},
            {"getpgrp", __NR_getpgrp},
            {"setpgid", __NR_setpgid},
            {"setsid", __NR_setsid},
            
            // 用户/组 ID
            {"getuid", __NR_getuid},
            {"geteuid", __NR_geteuid},
            {"getgid", __NR_getgid},
            {"getegid", __NR_getegid},
            {"setuid", __NR_setuid},
            {"setgid", __NR_setgid},
            {"setreuid", __NR_setreuid},
            {"setregid", __NR_setregid},
            {"getgroups", __NR_getgroups},
            {"setgroups", __NR_setgroups},
            
            // 信号
            {"rt_sigaction", __NR_rt_sigaction},
            {"rt_sigprocmask", __NR_rt_sigprocmask},
            {"rt_sigreturn", __NR_rt_sigreturn},
            {"sigaltstack", __NR_sigaltstack},
            
            // 时间
            {"gettimeofday", __NR_gettimeofday},
            {"clock_gettime", __NR_clock_gettime},
            {"clock_getres", __NR_clock_getres},
            {"clock_nanosleep", __NR_clock_nanosleep},
            {"nanosleep", __NR_nanosleep},
            {"times", __NR_times},
            
            // 系统信息
            {"uname", __NR_uname},
            {"sysinfo", __NR_sysinfo},
            {"getrlimit", __NR_getrlimit},
            {"setrlimit", __NR_setrlimit},
            {"prlimit64", __NR_prlimit64},
            {"getrusage", __NR_getrusage},
            {"prctl", __NR_prctl},
            {"arch_prctl", __NR_arch_prctl},
            {"getrandom", __NR_getrandom},
            
            // 同步
            {"futex", __NR_futex},
            {"set_tid_address", __NR_set_tid_address},
            {"set_robust_list", __NR_set_robust_list},
            {"sched_yield", __NR_sched_yield},
            {"sched_getaffinity", __NR_sched_getaffinity},
#ifdef __NR_rseq
            {"rseq", __NR_rseq},
#endif
            
            // 网络
            {"socket", __NR_socket},
            {"connect", __NR_connect},
            {"accept", __NR_accept},
            {"bind", __NR_bind},
            {"listen", __NR_listen},
            {"sendto", __NR_sendto},
            {"recvfrom", __NR_recvfrom},
            {"shutdown", __NR_shutdown},
            {"getsockname", __NR_getsockname},
            {"getpeername", __NR_getpeername},
            {"setsockopt", __NR_setsockopt},
            {"getsockopt", __NR_getsockopt},
            
            // I/O 控制
            {"ioctl", __NR_ioctl},
            {"poll", __NR_poll},
            {"ppoll", __NR_ppoll},
            {"select", __NR_select},
            {"pselect6", __NR_pselect6},
            
            // Epoll
            {"epoll_create1", __NR_epoll_create1},
            {"epoll_ctl", __NR_epoll_ctl},
            {"epoll_pwait", __NR_epoll_pwait},
            {"eventfd2", __NR_eventfd2},
            
            // io_uring
            {"io_uring_setup", __NR_io_uring_setup},
            {"io_uring_enter", __NR_io_uring_enter},
            {"io_uring_register", __NR_io_uring_register},
            
            // 文件系统
            {"statfs", __NR_statfs},
            {"fstatfs", __NR_fstatfs},
            {"umask", __NR_umask},
            {"chmod", __NR_chmod},
            {"fchmod", __NR_fchmod},
            {"chown", __NR_chown},
            {"fchown", __NR_fchown},
            {"lchown", __NR_lchown},
            {"link", __NR_link},
            {"symlink", __NR_symlink},
            {"creat", __NR_creat},
        };
    }
    
    std::map<std::string, int> map_;
};

// 便捷函数
inline int syscall_name_to_nr(const std::string& name) {
    return SyscallMap::instance().name_to_nr(name);
}

inline std::string syscall_nr_to_name(int nr) {
    return SyscallMap::instance().nr_to_name(nr);
}

} // namespace uoj

#endif // UOJ_CORE_SYSCALL_MAP_H

