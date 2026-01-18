/**
 * @file namespace.h
 * @brief Linux 命名空间隔离
 * 
 * 使用 Linux namespaces 实现进程隔离，这是容器技术的基础。
 * 
 * 支持的命名空间：
 * - PID namespace: 隔离进程 ID
 * - Mount namespace: 隔离文件系统挂载
 * - Network namespace: 隔离网络
 * - User namespace: 隔离用户/组 ID
 * - UTS namespace: 隔离主机名
 * - IPC namespace: 隔离 IPC 资源
 */

#ifndef UOJ_SANDBOX_NAMESPACE_H
#define UOJ_SANDBOX_NAMESPACE_H

#include <string>
#include <vector>
#include <functional>
#include <filesystem>

#include <sched.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <signal.h>

#include "core/error.h"

namespace uoj {
namespace sandbox {

namespace fs = std::filesystem;

//==============================================================================
// 命名空间标志
//==============================================================================

/**
 * @brief 命名空间类型
 */
enum class NamespaceType {
    NONE    = 0,
    PID     = CLONE_NEWPID,    ///< 进程 ID 命名空间
    MOUNT   = CLONE_NEWNS,     ///< 挂载命名空间
    NETWORK = CLONE_NEWNET,    ///< 网络命名空间
    USER    = CLONE_NEWUSER,   ///< 用户命名空间
    UTS     = CLONE_NEWUTS,    ///< UTS 命名空间
    IPC     = CLONE_NEWIPC,    ///< IPC 命名空间
    CGROUP  = CLONE_NEWCGROUP, ///< Cgroup 命名空间
};

inline int operator|(NamespaceType a, NamespaceType b) {
    return static_cast<int>(a) | static_cast<int>(b);
}

inline int operator|(int a, NamespaceType b) {
    return a | static_cast<int>(b);
}

//==============================================================================
// 挂载点配置
//==============================================================================

/**
 * @brief 挂载类型
 */
enum class MountType {
    BIND,       ///< 绑定挂载
    BIND_RO,    ///< 只读绑定挂载
    TMPFS,      ///< 临时文件系统
    PROC,       ///< /proc 文件系统
    DEVPTS,     ///< /dev/pts
    OVERLAY,    ///< OverlayFS
};

/**
 * @brief 挂载点配置
 */
struct MountPoint {
    MountType type;
    std::string source;
    std::string target;
    std::string options;
    
    MountPoint(MountType t, const std::string &src, const std::string &tgt,
               const std::string &opts = "")
        : type(t), source(src), target(tgt), options(opts) {}
    
    // 便捷构造函数
    static MountPoint bind(const std::string &src, const std::string &tgt) {
        return {MountType::BIND, src, tgt, ""};
    }
    
    static MountPoint bind_ro(const std::string &src, const std::string &tgt) {
        return {MountType::BIND_RO, src, tgt, ""};
    }
    
    static MountPoint tmpfs(const std::string &tgt, const std::string &opts = "size=64m") {
        return {MountType::TMPFS, "tmpfs", tgt, opts};
    }
    
    static MountPoint proc(const std::string &tgt = "/proc") {
        return {MountType::PROC, "proc", tgt, ""};
    }
};

//==============================================================================
// 命名空间配置
//==============================================================================

/**
 * @brief 命名空间沙箱配置
 */
struct NamespaceConfig {
    int flags;                          ///< 命名空间标志
    std::string rootfs;                 ///< 根文件系统路径
    std::string hostname;               ///< 主机名
    std::string work_dir;               ///< 工作目录
    
    uid_t uid;                          ///< 容器内 UID
    gid_t gid;                          ///< 容器内 GID
    
    std::vector<MountPoint> mounts;     ///< 挂载点列表
    std::vector<std::string> env;       ///< 环境变量
    
    NamespaceConfig()
        : flags(0), uid(65534), gid(65534) {}
    
    // 链式配置
    NamespaceConfig& enable_pid_ns() {
        flags |= CLONE_NEWPID;
        return *this;
    }
    
    NamespaceConfig& enable_mount_ns() {
        flags |= CLONE_NEWNS;
        return *this;
    }
    
    NamespaceConfig& enable_net_ns() {
        flags |= CLONE_NEWNET;
        return *this;
    }
    
    NamespaceConfig& enable_user_ns() {
        flags |= CLONE_NEWUSER;
        return *this;
    }
    
    NamespaceConfig& enable_uts_ns() {
        flags |= CLONE_NEWUTS;
        return *this;
    }
    
    NamespaceConfig& enable_ipc_ns() {
        flags |= CLONE_NEWIPC;
        return *this;
    }
    
    NamespaceConfig& set_rootfs(const std::string &path) {
        rootfs = path;
        return *this;
    }
    
    NamespaceConfig& set_hostname(const std::string &name) {
        hostname = name;
        return *this;
    }
    
    NamespaceConfig& set_workdir(const std::string &dir) {
        work_dir = dir;
        return *this;
    }
    
    NamespaceConfig& set_uid_gid(uid_t u, gid_t g) {
        uid = u;
        gid = g;
        return *this;
    }
    
    NamespaceConfig& add_mount(const MountPoint &mp) {
        mounts.push_back(mp);
        return *this;
    }
    
    NamespaceConfig& add_env(const std::string &e) {
        env.push_back(e);
        return *this;
    }
};

//==============================================================================
// 命名空间执行器
//==============================================================================

/**
 * @brief 子进程入口函数类型
 */
using ChildFunc = std::function<int()>;

/**
 * @brief 命名空间执行器
 */
class NamespaceExecutor {
private:
    NamespaceConfig config_;
    
    /**
     * @brief 设置用户映射
     */
    static Result<void> setup_user_mapping(pid_t pid, uid_t uid, gid_t gid) {
        // 写入 uid_map
        std::string uid_map_path = "/proc/" + std::to_string(pid) + "/uid_map";
        std::ofstream uid_map(uid_map_path);
        if (!uid_map) {
            return Err<void>(ErrorCode::FILE_WRITE_ERROR, "Cannot open uid_map");
        }
        uid_map << uid << " " << getuid() << " 1\n";
        uid_map.close();
        
        // 禁用 setgroups
        std::string setgroups_path = "/proc/" + std::to_string(pid) + "/setgroups";
        std::ofstream setgroups(setgroups_path);
        if (setgroups) {
            setgroups << "deny\n";
            setgroups.close();
        }
        
        // 写入 gid_map
        std::string gid_map_path = "/proc/" + std::to_string(pid) + "/gid_map";
        std::ofstream gid_map(gid_map_path);
        if (!gid_map) {
            return Err<void>(ErrorCode::FILE_WRITE_ERROR, "Cannot open gid_map");
        }
        gid_map << gid << " " << getgid() << " 1\n";
        gid_map.close();
        
        return Ok();
    }

    /**
     * @brief 执行挂载
     */
    static Result<void> do_mount(const MountPoint &mp, const std::string &rootfs) {
        std::string target = rootfs + mp.target;
        
        // 确保目标目录存在
        fs::create_directories(target);
        
        int flags = 0;
        const char *fstype = nullptr;
        const char *source = mp.source.c_str();
        const char *data = mp.options.empty() ? nullptr : mp.options.c_str();
        
        switch (mp.type) {
            case MountType::BIND:
                flags = MS_BIND | MS_REC;
                break;
                
            case MountType::BIND_RO:
                flags = MS_BIND | MS_REC;
                if (mount(source, target.c_str(), nullptr, flags, nullptr) < 0) {
                    return Err<void>(ErrorCode::SYSTEM_ERROR, 
                                   "Bind mount failed: " + mp.source);
                }
                // 重新挂载为只读
                flags = MS_BIND | MS_REC | MS_RDONLY | MS_REMOUNT;
                break;
                
            case MountType::TMPFS:
                fstype = "tmpfs";
                break;
                
            case MountType::PROC:
                fstype = "proc";
                source = "proc";
                break;
                
            case MountType::DEVPTS:
                fstype = "devpts";
                source = "devpts";
                data = "newinstance,ptmxmode=0666";
                break;
                
            default:
                return Err<void>(ErrorCode::SYSTEM_ERROR, "Unknown mount type");
        }
        
        if (mount(source, target.c_str(), fstype, flags, data) < 0) {
            return Err<void>(ErrorCode::SYSTEM_ERROR,
                           "Mount failed: " + mp.source + " -> " + target);
        }
        
        return Ok();
    }

    /**
     * @brief 设置根文件系统
     */
    Result<void> setup_rootfs() {
        if (config_.rootfs.empty()) {
            return Ok();
        }
        
        // 将根文件系统设为 private，防止挂载传播
        if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) {
            return Err<void>(ErrorCode::SYSTEM_ERROR, "Cannot set / as private");
        }
        
        // 执行所有挂载
        for (const auto &mp : config_.mounts) {
            UOJ_TRY(do_mount(mp, config_.rootfs));
        }
        
        // pivot_root
        std::string old_root = config_.rootfs + "/old_root";
        fs::create_directories(old_root);
        
        if (syscall(SYS_pivot_root, config_.rootfs.c_str(), old_root.c_str()) < 0) {
            // 如果 pivot_root 失败，尝试 chroot
            if (chroot(config_.rootfs.c_str()) < 0) {
                return Err<void>(ErrorCode::SYSTEM_ERROR, "Cannot chroot");
            }
        } else {
            // 卸载旧根
            if (umount2("/old_root", MNT_DETACH) < 0) {
                // 忽略错误
            }
            rmdir("/old_root");
        }
        
        // 切换到工作目录
        if (!config_.work_dir.empty()) {
            if (chdir(config_.work_dir.c_str()) < 0) {
                return Err<void>(ErrorCode::SYSTEM_ERROR, 
                               "Cannot chdir to " + config_.work_dir);
            }
        } else {
            chdir("/");
        }
        
        return Ok();
    }

public:
    explicit NamespaceExecutor(const NamespaceConfig &config)
        : config_(config) {}

    /**
     * @brief 在新命名空间中执行函数
     */
    Result<pid_t> run(const ChildFunc &func) {
        // 创建管道用于同步
        int pipe_fd[2];
        if (pipe(pipe_fd) < 0) {
            return Err<pid_t>(ErrorCode::PIPE_FAILED, "Cannot create pipe");
        }
        
        // 准备 clone 标志
        int clone_flags = config_.flags | SIGCHLD;
        
        // 使用 clone 创建子进程
        pid_t pid = syscall(SYS_clone, clone_flags, nullptr, nullptr, nullptr, 0);
        
        if (pid < 0) {
            close(pipe_fd[0]);
            close(pipe_fd[1]);
            return Err<pid_t>(ErrorCode::FORK_FAILED, "Clone failed");
        }
        
        if (pid == 0) {
            // 子进程
            close(pipe_fd[1]);  // 关闭写端
            
            // 等待父进程设置用户映射
            if (config_.flags & CLONE_NEWUSER) {
                char buf;
                read(pipe_fd[0], &buf, 1);
            }
            close(pipe_fd[0]);
            
            // 设置主机名
            if (!config_.hostname.empty() && (config_.flags & CLONE_NEWUTS)) {
                sethostname(config_.hostname.c_str(), config_.hostname.size());
            }
            
            // 设置根文件系统
            if (config_.flags & CLONE_NEWNS) {
                auto result = setup_rootfs();
                if (result.is_error()) {
                    _exit(127);
                }
            }
            
            // 执行用户函数
            int ret = func();
            _exit(ret);
        }
        
        // 父进程
        close(pipe_fd[0]);  // 关闭读端
        
        // 设置用户映射
        if (config_.flags & CLONE_NEWUSER) {
            auto result = setup_user_mapping(pid, config_.uid, config_.gid);
            if (result.is_error()) {
                kill(pid, SIGKILL);
                waitpid(pid, nullptr, 0);
                close(pipe_fd[1]);
                return Err<pid_t>(result.error());
            }
        }
        
        // 通知子进程继续
        write(pipe_fd[1], "x", 1);
        close(pipe_fd[1]);
        
        return Result<pid_t>(pid);
    }

    /**
     * @brief 在新命名空间中执行程序
     */
    Result<pid_t> exec(const std::string &program, 
                       const std::vector<std::string> &args) {
        return run([&]() -> int {
            // 构建参数数组
            std::vector<const char*> argv;
            argv.push_back(program.c_str());
            for (const auto &arg : args) {
                argv.push_back(arg.c_str());
            }
            argv.push_back(nullptr);
            
            // 构建环境变量数组
            std::vector<const char*> envp;
            for (const auto &e : config_.env) {
                envp.push_back(e.c_str());
            }
            envp.push_back(nullptr);
            
            // 执行程序
            execve(program.c_str(), 
                   const_cast<char* const*>(argv.data()),
                   const_cast<char* const*>(envp.data()));
            
            return 127;  // execve 失败
        });
    }
};

//==============================================================================
// 预定义配置
//==============================================================================

/**
 * @brief 创建评测机命名空间配置
 */
inline NamespaceConfig create_judge_ns_config(
    const std::string &rootfs,
    const std::string &workdir
) {
    NamespaceConfig config;
    
    config.enable_pid_ns()      // 隔离进程
          .enable_mount_ns()    // 隔离挂载
          .enable_net_ns()      // 禁用网络
          .enable_ipc_ns()      // 隔离 IPC
          .enable_uts_ns()      // 隔离主机名
          .set_rootfs(rootfs)
          .set_hostname("sandbox")
          .set_workdir(workdir)
          .set_uid_gid(65534, 65534);  // nobody
    
    // 基本挂载
    config.add_mount(MountPoint::proc())
          .add_mount(MountPoint::tmpfs("/tmp"))
          .add_mount(MountPoint::tmpfs("/dev", "mode=755"));
    
    // 只读绑定系统目录
    config.add_mount(MountPoint::bind_ro("/usr", "/usr"))
          .add_mount(MountPoint::bind_ro("/lib", "/lib"))
          .add_mount(MountPoint::bind_ro("/lib64", "/lib64"))
          .add_mount(MountPoint::bind_ro("/bin", "/bin"));
    
    // 环境变量
    config.add_env("PATH=/usr/bin:/bin")
          .add_env("HOME=/tmp")
          .add_env("LANG=C.UTF-8");
    
    return config;
}

/**
 * @brief 检查命名空间功能是否可用
 */
inline bool is_namespace_available() {
    // 尝试创建用户命名空间
    int pid = syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, nullptr, nullptr, nullptr, 0);
    if (pid < 0) {
        return false;
    }
    if (pid == 0) {
        _exit(0);
    }
    waitpid(pid, nullptr, 0);
    return true;
}

} // namespace sandbox
} // namespace uoj

#endif // UOJ_SANDBOX_NAMESPACE_H

