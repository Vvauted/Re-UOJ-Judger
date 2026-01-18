/**
 * @file sandbox.h
 * @brief 现代化沙箱系统
 * 
 * 整合 seccomp-bpf、cgroups v2 和 namespaces，提供高性能安全沙箱。
 */

#ifndef UOJ_SANDBOX_SANDBOX_H
#define UOJ_SANDBOX_SANDBOX_H

#include <string>
#include <vector>
#include <set>
#include <memory>
#include <chrono>
#include <atomic>
#include <thread>
#include <functional>
#include <cstring>
#include <climits>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <dirent.h>

#include "core/error.h"
#include "core/types.h"
#include "core/logger.h"
#include "core/user.h"
#include "sandbox/seccomp.h"
#include "sandbox/cgroup.h"
#include "sandbox/namespace.h"

namespace uoj {
namespace sandbox {

//==============================================================================
// 沙箱执行结果
//==============================================================================

enum class RunStatus {
    OK,
    TIME_LIMIT,
    MEMORY_LIMIT,
    OUTPUT_LIMIT,
    RUNTIME_ERROR,
    KILLED_BY_SIGNAL,
    SECCOMP_VIOLATION,
    INTERNAL_ERROR
};

inline const char* status_to_string(RunStatus status) {
    switch (status) {
        case RunStatus::OK: return "OK";
        case RunStatus::TIME_LIMIT: return "TIME_LIMIT";
        case RunStatus::MEMORY_LIMIT: return "MEMORY_LIMIT";
        case RunStatus::OUTPUT_LIMIT: return "OUTPUT_LIMIT";
        case RunStatus::RUNTIME_ERROR: return "RUNTIME_ERROR";
        case RunStatus::KILLED_BY_SIGNAL: return "KILLED_BY_SIGNAL";
        case RunStatus::SECCOMP_VIOLATION: return "SECCOMP_VIOLATION";
        case RunStatus::INTERNAL_ERROR: return "INTERNAL_ERROR";
        default: return "UNKNOWN";
    }
}

inline std::ostream& operator<<(std::ostream &os, RunStatus status) {
    return os << status_to_string(status);
}

struct SandboxResult {
    RunStatus status;
    int exit_code;
    int signal;
    uint64_t time_ms;
    uint64_t real_time_ms;
    uint64_t memory_bytes;
    uint64_t memory_kb;
    std::string message;
    
    SandboxResult()
        : status(RunStatus::INTERNAL_ERROR), exit_code(-1), signal(0),
          time_ms(0), real_time_ms(0), memory_bytes(0), memory_kb(0) {}
    
    bool ok() const { return status == RunStatus::OK && exit_code == 0; }
    
    RunResult to_run_result() const {
        int type;
        switch (status) {
            case RunStatus::OK:
                type = (exit_code == 0) ? RS_AC : RS_RE;
                break;
            case RunStatus::TIME_LIMIT:
                type = RS_TLE;
                break;
            case RunStatus::MEMORY_LIMIT:
                type = RS_MLE;
                break;
            case RunStatus::SECCOMP_VIOLATION:
                type = RS_DGS;
                break;
            default:
                type = RS_RE;
        }
        return RunResult(type, time_ms, memory_kb, exit_code);
    }
};

//==============================================================================
// 沙箱配置（简化版）
//==============================================================================

struct SandboxConfig {
    // 资源限制
    int time_limit_ms = 1000;
    int real_time_limit_ms = 0;    // 0 = auto
    int memory_limit_kb = 262144;  // 256 MB
    int output_limit_kb = 65536;   // 64 MB
    int max_processes = 1;
    int stack_limit_kb = 8192;     // 8 MB
    
    // 文件重定向
    std::string stdin_file;
    std::string stdout_file;
    std::string stderr_file;
    
    // 工作目录
    std::string work_dir;
    
    // 安全选项
    bool use_seccomp = true;
    bool use_cgroup = true;
    bool use_namespace = true;
    bool allow_network = false;
    bool disable_address_limit = false;
    
    // 可执行文件
    std::string program;
    std::vector<std::string> args;
    std::vector<std::string> env;
    
    // 文件系统沙箱（统一配置）
    FsSandboxConfig sandbox;
    
    // 允许的系统调用
    std::set<int> allowed_syscalls;
    
    // 从 RunLimit 构造
    static SandboxConfig from_run_limit(const RunLimit &limit) {
        SandboxConfig cfg;
        cfg.time_limit_ms = limit.time * 1000;
        cfg.memory_limit_kb = limit.memory * 1024;
        cfg.output_limit_kb = limit.output * 1024;
        if (limit.real_time > 0) {
            cfg.real_time_limit_ms = limit.real_time * 1000;
        }
        return cfg;
    }
    
    // 从 UserConfig 构造
    static SandboxConfig from_user(const UserConfig &user) {
        SandboxConfig cfg;
        
        // Seccomp
        cfg.use_seccomp = user.use_seccomp;
        cfg.allowed_syscalls = user.allowed_syscalls;
        
        // Namespace
        cfg.use_namespace = user.use_namespace;
        cfg.allow_network = !user.ns_network;
        
        // Cgroup
        cfg.use_cgroup = user.use_cgroup;
        if (user.memory_limit_bytes > 0) {
            cfg.memory_limit_kb = user.memory_limit_bytes / 1024;
        }
        if (user.max_processes > 0) {
            cfg.max_processes = user.max_processes;
        } else if (!user.use_cgroup) {
            // cgroup 禁用时不限制进程数
            cfg.max_processes = 0;
        }
        
        // 文件系统沙箱
        cfg.sandbox = user.sandbox;
        
        // Rlimit
        if (user.rlimit_fsize > 0) {
            cfg.output_limit_kb = user.rlimit_fsize / 1024;
        }
        if (user.rlimit_as > 0) {
            cfg.memory_limit_kb = user.rlimit_as / 1024;
        } else if (user.rlimit_as == -1) {
            cfg.disable_address_limit = true;
        }
        if (user.rlimit_stack > 0) {
            cfg.stack_limit_kb = user.rlimit_stack / 1024;
        }
        
        // 工作目录
        cfg.work_dir = user.work_dir;
        
        // 环境变量
        for (const auto& kv : user.env) {
            cfg.env.push_back(kv.first + "=" + kv.second);
        }
        
        return cfg;
    }
    
    // 链式配置
    SandboxConfig& set_time_limit(int ms) { time_limit_ms = ms; return *this; }
    SandboxConfig& set_memory_limit(int kb) { memory_limit_kb = kb; return *this; }
    SandboxConfig& set_program(const std::string &prog) { program = prog; return *this; }
    SandboxConfig& add_arg(const std::string &arg) { args.push_back(arg); return *this; }
    SandboxConfig& set_workdir(const std::string &dir) { work_dir = dir; return *this; }
    SandboxConfig& redirect_stdin(const std::string &file) { stdin_file = file; return *this; }
    SandboxConfig& redirect_stdout(const std::string &file) { stdout_file = file; return *this; }
    SandboxConfig& redirect_stderr(const std::string &file) { stderr_file = file; return *this; }
};

//==============================================================================
// 沙箱执行器
//==============================================================================

class Sandbox {
private:
    SandboxConfig config_;
    std::unique_ptr<CgroupController> cgroup_;
    std::string cgroup_name_;
    static std::atomic<int> instance_counter_;

    /**
     * @brief 设置资源限制
     */
    static void setup_rlimits(const SandboxConfig &config) {
        struct rlimit rl;
        
        // CPU 时间
        rl.rlim_cur = (config.time_limit_ms + 999) / 1000 + 1;
        rl.rlim_max = rl.rlim_cur + 1;
        setrlimit(RLIMIT_CPU, &rl);
        
        // 地址空间
        if (!config.disable_address_limit) {
            rl.rlim_cur = rl.rlim_max = config.memory_limit_kb * 1024ULL * 2;
            setrlimit(RLIMIT_AS, &rl);
        }
        
        // 栈大小 = 内存限制（不单独配置）
        rl.rlim_cur = rl.rlim_max = config.memory_limit_kb * 1024ULL;
        setrlimit(RLIMIT_STACK, &rl);
        
        // 文件大小
        rl.rlim_cur = rl.rlim_max = config.output_limit_kb * 1024ULL;
        setrlimit(RLIMIT_FSIZE, &rl);
        
        // Core dump
        rl.rlim_cur = rl.rlim_max = 0;
        setrlimit(RLIMIT_CORE, &rl);
    }

    /**
     * @brief 重定向标准IO
     */
    static bool setup_io_redirect(const SandboxConfig &config) {
        if (!config.stdin_file.empty()) {
            int fd = open(config.stdin_file.c_str(), O_RDONLY);
            if (fd < 0) return false;
            dup2(fd, STDIN_FILENO);
            close(fd);
        }
        
        if (!config.stdout_file.empty()) {
            int fd = open(config.stdout_file.c_str(), 
                         O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) return false;
            dup2(fd, STDOUT_FILENO);
            close(fd);
        }
        
        if (!config.stderr_file.empty()) {
            int fd = open(config.stderr_file.c_str(),
                         O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) return false;
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        
        return true;
    }

    /**
     * @brief 创建目录路径
     */
    static void mkpath(const char* path) {
        char* dir = strdup(path);
        for (char* p = dir + 1; *p; p++) {
            if (*p == '/') { *p = '\0'; mkdir(dir, 0755); *p = '/'; }
        }
        mkdir(dir, 0755);
        free(dir);
    }

    /**
     * @brief 解析 tmpfs 大小（如 "16m" -> "size=16m"）
     */
    static std::string parse_tmpfs_size(const std::string& size) {
        if (size.empty()) return "size=16m";
        return "size=" + size;
    }

    /**
     * @brief 获取设备号
     */
    static dev_t get_device_number(const std::string& dev) {
        if (dev == "/dev/null") return makedev(1, 3);
        if (dev == "/dev/zero") return makedev(1, 5);
        if (dev == "/dev/urandom" || dev == "/dev/random") return makedev(1, 9);
        if (dev == "/dev/tty") return makedev(5, 0);
        return 0;
    }

    /**
     * @brief 使用 pivot_root 创建最小根文件系统（参考 nsjail）
     */
    static bool setup_pivot_root(const SandboxConfig &config) {
        const auto& sb = config.sandbox;
        
        // 注意：MS_REC | MS_PRIVATE 已在 child_exec 中调用过，这里不再重复
        
        // 1. 创建新根目录
        char newroot[PATH_MAX];
        // 尝试多个位置
        const char* dirs[] = {"/run", "/dev/shm", "/tmp"};
        bool created = false;
        for (const char* dir : dirs) {
            snprintf(newroot, sizeof(newroot), "%s/.sandbox_XXXXXX", dir);
            if (mkdtemp(newroot)) {
                created = true;
                break;
            }
        }
        if (!created) {
            return false;
        }
        
        // 2. 在新根上挂载 tmpfs
        if (mount("tmpfs", newroot, "tmpfs", MS_NOSUID | MS_NODEV, "size=64m") != 0) {
            rmdir(newroot);
            return false;
        }
        
        // 3. 辅助函数：bind mount 或创建符号链接
        auto bind_mount = [&newroot](const std::string& src, bool readonly) {
            struct stat lst;
            if (lstat(src.c_str(), &lst) != 0) {
                return true;  // 源不存在，跳过
            }
            
            char target[PATH_MAX];
            snprintf(target, sizeof(target), "%s%s", newroot, src.c_str());
            
            // 确保父目录存在
            char* parent = strdup(target);
            char* lastslash = strrchr(parent, '/');
            if (lastslash && lastslash != parent) { 
                *lastslash = '\0'; 
                mkpath(parent); 
            }
            free(parent);
            
            // 如果是符号链接，创建相同的符号链接（nsjail 做法）
            if (S_ISLNK(lst.st_mode)) {
                char linktarget[PATH_MAX];
                ssize_t len = readlink(src.c_str(), linktarget, sizeof(linktarget) - 1);
                if (len > 0) {
                    linktarget[len] = '\0';
                    symlink(linktarget, target);
                }
                return true;
            }
            
            // 创建挂载点（目录或文件）
            bool is_dir = S_ISDIR(lst.st_mode);
            if (is_dir) {
                int mkret = mkdir(target, 0755);
                if (mkret != 0 && errno != EEXIST) {
                    return false;
                }
                struct stat mst;
                if (stat(target, &mst) != 0) {
                    return false;
                }
            } else {
                int fd = open(target, O_CREAT | O_RDONLY, 0644);
                if (fd >= 0) close(fd);
            }
            
            if (mount(src.c_str(), target, nullptr, MS_BIND | MS_REC, nullptr) != 0) {
                return false;
            }
            
            if (readonly) {
                mount(nullptr, target, nullptr, 
                      MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID, nullptr);
            }
            return true;
        };
        
        // 4. 挂载只读路径
        for (const auto& path : sb.readonly) {
            bind_mount(path, true);
        }
        
        // 5. 创建 tmpfs 挂载（在工作目录之前，避免覆盖）
        for (const auto& [path, size] : sb.tmpfs) {
            char target[PATH_MAX];
            snprintf(target, sizeof(target), "%s%s", newroot, path.c_str());
            mkpath(target);
            std::string opts = parse_tmpfs_size(size);
            // /dev 目录不能使用 MS_NODEV，否则设备节点无法工作
            unsigned long flags = MS_NOSUID;
            if (path != "/dev") {
                flags |= MS_NODEV;
            }
            mount("tmpfs", target, "tmpfs", flags, opts.c_str());
            
            // 如果是 /tmp，设置正确权限
            if (path == "/tmp") {
                chmod(target, 01777);
            }
        }
        
        // 6. 挂载可写路径（在 tmpfs 之后，这样子目录能正确挂载）
        for (const auto& path : sb.writable) {
            bind_mount(path, false);
        }
        
        // 7. 挂载工作目录（可写）
        if (!config.work_dir.empty()) {
            bind_mount(config.work_dir, false);
        }
        
        // 8. 创建设备节点
        if (!sb.devices.empty()) {
            char devdir[PATH_MAX];
            snprintf(devdir, sizeof(devdir), "%s/dev", newroot);
            
            // 确保 /dev 存在
            struct stat st;
            if (stat(devdir, &st) != 0) {
                mkdir(devdir, 0755);
            }
            
            for (const auto& dev : sb.devices) {
                char devpath[PATH_MAX];
                snprintf(devpath, sizeof(devpath), "%s%s", newroot, dev.c_str());
                
                dev_t devnum = get_device_number(dev);
                if (devnum != 0) {
                    if (mknod(devpath, S_IFCHR | 0666, devnum) != 0) {
                        // mknod 失败，尝试 bind mount
                        int fd = open(devpath, O_CREAT | O_RDONLY, 0644);
                        if (fd >= 0) close(fd);
                        mount(dev.c_str(), devpath, nullptr, MS_BIND, nullptr);
                    }
                }
            }
        }
        
        // 9. pivot_root (nsjail 风格)
        if (syscall(__NR_pivot_root, newroot, newroot) == 0) {
            umount2("/", MNT_DETACH);
            (void)chdir("/");
            return true;
        }
        
        // pivot_root 失败，回退到 chroot
        if (chroot(newroot) != 0) {
            return false;
        }
        (void)chdir("/");
        return true;
    }

    /**
     * @brief 设置文件系统隔离
     */
    static void setup_fs_isolation(const SandboxConfig &config) {
        
        if (config.sandbox.mode == SandboxMode::None) {
            return;
        }
        
        if (config.sandbox.mode == SandboxMode::PivotRoot) {
            if (setup_pivot_root(config)) {
                return;
            }
            _exit(127);
        }
    }

    /**
     * @brief 构建 seccomp 过滤器
     */
    static void apply_seccomp_filter(const std::set<int> &allowed_syscalls) {
        size_t total = allowed_syscalls.size();
        size_t prog_len = 4 + total + 2;
        
        struct sock_filter *filter = (struct sock_filter*)malloc(prog_len * sizeof(struct sock_filter));
        if (!filter) _exit(127);
        
        size_t idx = 0;
        
        // 检查架构
        filter[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 
                                  offsetof(struct seccomp_data, arch));
        filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
        filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
        
        // 加载 syscall 号
        filter[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                  offsetof(struct seccomp_data, nr));
        
        // 检查允许的 syscall
        size_t remaining = total;
        for (int nr : allowed_syscalls) {
            remaining--;
            filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 
                                      (uint32_t)nr, (uint8_t)(remaining + 1), 0);
        }
        
        // 默认 KILL
        filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
        // ALLOW 目标
        filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        
        struct sock_fprog prog = { .len = (unsigned short)idx, .filter = filter };
        
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            free(filter);
            _exit(127);
        }
        
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
            free(filter);
            _exit(127);
        }
        
        free(filter);
    }

    /**
     * @brief 子进程执行
     */
    static void child_exec(const SandboxConfig &config) {
        // 1. 设置 namespace 隔离
        if (config.use_namespace) {
            int ns_flags = CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS;
            if (!config.allow_network) {
                ns_flags |= CLONE_NEWNET;
            }
            
            if (unshare(ns_flags) == 0) {
                mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr);
                setup_fs_isolation(config);
                sethostname("sandbox", 7);
            }
        }
        
        // 2. 切换工作目录
        if (!config.work_dir.empty()) {
            if (chdir(config.work_dir.c_str()) < 0) {
                _exit(127);
            }
        }
        
        // 3. 设置 IO 重定向
        if (!setup_io_redirect(config)) {
            _exit(127);
        }
        
        // 4. 设置 rlimits
        setup_rlimits(config);
        
        // 5. 设置 seccomp
        // 注意：IO 已重定向，不要在这里输出调试信息
        if (config.use_seccomp && !config.allowed_syscalls.empty()) {
            apply_seccomp_filter(config.allowed_syscalls);
        }
        
        // 6. 构建参数和环境变量
        std::vector<const char*> argv;
        argv.push_back(config.program.c_str());
        for (const auto &arg : config.args) {
            argv.push_back(arg.c_str());
        }
        argv.push_back(nullptr);
        
        std::vector<const char*> envp;
        for (const auto &e : config.env) {
            envp.push_back(e.c_str());
        }
        envp.push_back("PATH=/usr/bin:/bin");
        envp.push_back("HOME=/tmp");
        envp.push_back(nullptr);
        
        // 7. 执行程序
        if (access(config.program.c_str(), X_OK) != 0) {
            _exit(127);
        }
        
        execve(config.program.c_str(),
               const_cast<char* const*>(argv.data()),
               const_cast<char* const*>(envp.data()));
        _exit(127);
    }

public:
    explicit Sandbox(const SandboxConfig &config)
        : config_(config) {
        cgroup_name_ = "sandbox_" + std::to_string(getpid()) + "_" +
                       std::to_string(++instance_counter_);
    }
    
    ~Sandbox() = default;

    /**
     * @brief 执行程序
     */
    Result<SandboxResult> run() {
        SandboxResult result;
        auto start_time = std::chrono::steady_clock::now();
        
        // 1. 创建 cgroup
        if (config_.use_cgroup && is_cgroup_v2_available()) {
            cgroup_ = std::make_unique<CgroupController>(cgroup_name_);
            auto cg_result = cgroup_->create();
            if (cg_result.is_error()) {
                LOG_WARN << "Cgroup creation failed, running without cgroup";
                cgroup_.reset();
            } else {
                CgroupLimits limits;
                limits.set_memory(config_.memory_limit_kb / 1024 + 16)
                      .disable_swap();
                if (config_.max_processes > 0) {
                    limits.set_max_pids(config_.max_processes + 2);
                }
                cgroup_->apply_limits(limits);
            }
        }
        
        // 2. 创建同步管道
        int sync_pipe[2];
        if (pipe(sync_pipe) < 0) {
            result.status = RunStatus::INTERNAL_ERROR;
            result.message = "Pipe creation failed";
            return Ok(std::move(result));
        }
        
        // 3. Fork 子进程
        pid_t pid = fork();
        
        if (pid < 0) {
            close(sync_pipe[0]);
            close(sync_pipe[1]);
            result.status = RunStatus::INTERNAL_ERROR;
            result.message = "Fork failed";
            return Ok(std::move(result));
        }
        
        if (pid == 0) {
            // 子进程
            close(sync_pipe[1]);
            char buf;
            read(sync_pipe[0], &buf, 1);
            close(sync_pipe[0]);
            
            child_exec(config_);
            _exit(127);
        }
        
        // 父进程
        close(sync_pipe[0]);
        
        // 4. 将子进程加入 cgroup
        if (cgroup_) {
            cgroup_->add_process(pid);
        }
        
        // 5. 通知子进程继续
        write(sync_pipe[1], "x", 1);
        close(sync_pipe[1]);
        
        // 6. 等待子进程
        int status;
        int real_time_limit = config_.real_time_limit_ms;
        if (real_time_limit <= 0) {
            real_time_limit = config_.time_limit_ms * 3 + 1000;
        }
        
        bool timed_out = false;
        auto deadline = start_time + std::chrono::milliseconds(real_time_limit);
        struct rusage child_usage;
        memset(&child_usage, 0, sizeof(child_usage));
        
        while (true) {
            // 使用 wait4 获取子进程的 rusage
            pid_t ret = wait4(pid, &status, WNOHANG, &child_usage);
            
            if (ret > 0) break;
            
            if (ret < 0) {
                if (errno == ECHILD) break;
                result.status = RunStatus::INTERNAL_ERROR;
                result.message = "Waitpid failed";
                return Ok(std::move(result));
            }
            
            if (std::chrono::steady_clock::now() >= deadline) {
                timed_out = true;
                kill(pid, SIGKILL);
                wait4(pid, &status, 0, &child_usage);
                break;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        
        // 7. 记录结束时间
        auto end_time = std::chrono::steady_clock::now();
        result.real_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();
        
        // 8. 获取资源使用（使用 wait4 返回的 child_usage）
        result.memory_kb = child_usage.ru_maxrss;
        result.memory_bytes = result.memory_kb * 1024;
        result.time_ms = child_usage.ru_utime.tv_sec * 1000 + 
                        child_usage.ru_utime.tv_usec / 1000;
        
        if (cgroup_) {
            auto stats = cgroup_->get_stats();
            
            // 使用 cgroup 的用户态 CPU 时间（与原始 UOJ 使用 rusage.ru_utime 一致）
            // 不使用 cpu_usage_usec（用户态+内核态总时间），因为那会多计算内核时间
            if (stats.cpu_user_usec > 0) {
                result.time_ms = stats.cpu_user_usec / 1000;
            }
            
            // 如果 cgroup memory.peak 可用，优先使用
            if (stats.memory_peak > 0) {
                result.memory_kb = stats.memory_peak / 1024;
                result.memory_bytes = stats.memory_peak;
            }
            
            if (stats.oom_killed) {
                result.status = RunStatus::MEMORY_LIMIT;
                result.message = "Killed by OOM";
                return Ok(std::move(result));
            }
        }
        
        // 9. 分析结果
        if (timed_out) {
            result.status = RunStatus::TIME_LIMIT;
            result.message = "Real time limit exceeded";
        } else if (WIFEXITED(status)) {
            result.exit_code = WEXITSTATUS(status);
            if (result.exit_code == 0) {
                result.status = RunStatus::OK;
            } else {
                result.status = RunStatus::RUNTIME_ERROR;
                result.message = "Exit code: " + std::to_string(result.exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            result.signal = WTERMSIG(status);
            
            switch (result.signal) {
                case SIGKILL:
                case SIGXCPU:
                    if (result.time_ms >= config_.time_limit_ms) {
                        result.status = RunStatus::TIME_LIMIT;
                        result.message = "CPU time limit exceeded";
                    } else if (result.memory_kb >= config_.memory_limit_kb) {
                        result.status = RunStatus::MEMORY_LIMIT;
                        result.message = "Memory limit exceeded";
                    } else {
                        result.status = RunStatus::KILLED_BY_SIGNAL;
                        result.message = "Killed by SIGKILL";
                    }
                    break;
                    
                case SIGXFSZ:
                    result.status = RunStatus::OUTPUT_LIMIT;
                    result.message = "Output limit exceeded";
                    break;
                    
                case SIGSYS:
                    result.status = RunStatus::SECCOMP_VIOLATION;
                    result.message = "Dangerous syscall";
                    break;
                    
                default:
                    result.status = RunStatus::RUNTIME_ERROR;
                    result.message = "Signal: " + std::to_string(result.signal);
            }
        }
        
        // 10. 检查资源限制
        if (result.status == RunStatus::OK || result.status == RunStatus::RUNTIME_ERROR) {
            if (result.time_ms > config_.time_limit_ms) {
                result.status = RunStatus::TIME_LIMIT;
            } else if (result.memory_kb > config_.memory_limit_kb) {
                result.status = RunStatus::MEMORY_LIMIT;
            }
        }
        
        return Ok(std::move(result));
    }

    const SandboxConfig& config() const { return config_; }
};

inline std::atomic<int> Sandbox::instance_counter_{0};

//==============================================================================
// 便捷函数
//==============================================================================

inline Result<SandboxResult> run_program(
    const std::string &program,
    const std::vector<std::string> &args,
    const RunLimit &limit,
    const std::string &work_dir = "",
    const std::string &stdin_file = "",
    const std::string &stdout_file = "",
    const std::string &stderr_file = ""
) {
    SandboxConfig config = SandboxConfig::from_run_limit(limit);
    config.program = program;
    config.args = args;
    config.work_dir = work_dir;
    config.stdin_file = stdin_file;
    config.stdout_file = stdout_file;
    config.stderr_file = stderr_file;
    
    Sandbox sandbox(config);
    return sandbox.run();
}

inline void check_sandbox_features() {
    LOG_INFO << "=== Sandbox Feature Check ===";
    LOG_INFO << "seccomp-bpf: always available (kernel 3.5+)";
    
    if (is_cgroup_v2_available()) {
        LOG_INFO << "cgroups v2: available";
    } else {
        LOG_WARN << "cgroups v2: not available";
    }
    
    if (is_namespace_available()) {
        LOG_INFO << "user namespaces: available";
    } else {
        LOG_WARN << "user namespaces: not available";
    }
}

} // namespace sandbox
} // namespace uoj

#endif // UOJ_SANDBOX_SANDBOX_H
