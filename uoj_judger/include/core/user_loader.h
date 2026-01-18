/**
 * @file user_loader.h
 * @brief User 配置加载器
 */

#ifndef UOJ_CORE_USER_LOADER_H
#define UOJ_CORE_USER_LOADER_H

#include "user.h"
#include "yaml_config.h"
#include <fstream>

namespace uoj {

/**
 * @brief 从 YAML 加载 FsSandboxConfig
 */
inline FsSandboxConfig load_sandbox_config(yaml::YamlNodePtr node) {
    FsSandboxConfig cfg;
    
    if (!node) return cfg;
    
    // 模式
    if (node->has("mode")) {
        cfg.mode = parse_sandbox_mode(node->get("mode")->as_string());
    }
    
    // 只读路径
    if (node->has("readonly")) {
        auto list = node->get("readonly")->as_list();
        for (const auto& item : list) {
            cfg.readonly.push_back(item->as_string());
        }
    }
    
    // 可写路径
    if (node->has("writable")) {
        auto list = node->get("writable")->as_list();
        for (const auto& item : list) {
            cfg.writable.push_back(item->as_string());
        }
    }
    
    // tmpfs（支持两种格式）
    if (node->has("tmpfs")) {
        auto tmpfs_node = node->get("tmpfs");
        // 格式1: 列表 ["/tmp: 16m", "/dev: 4m"]
        // 格式2: 映射 {/tmp: 16m, /dev: 4m}
        if (tmpfs_node->is_list()) {
            auto list = tmpfs_node->as_list();
            for (const auto& item : list) {
                std::string s = item->as_string();
                size_t pos = s.find(':');
                if (pos != std::string::npos) {
                    std::string path = s.substr(0, pos);
                    std::string size = s.substr(pos + 1);
                    while (!path.empty() && path.back() == ' ') path.pop_back();
                    while (!size.empty() && size.front() == ' ') size.erase(0, 1);
                    cfg.tmpfs[path] = size;
                } else {
                    cfg.tmpfs[s] = "16m";
                }
            }
        } else if (tmpfs_node->is_map()) {
            // 遍历 map（假设 yaml 库支持）
            // 简化处理：通过 has() 检查常见路径
            const char* common_tmpfs[] = {"/tmp", "/dev", "/dev/shm", nullptr};
            for (int i = 0; common_tmpfs[i]; i++) {
                if (tmpfs_node->has(common_tmpfs[i])) {
                    cfg.tmpfs[common_tmpfs[i]] = tmpfs_node->get(common_tmpfs[i])->as_string();
                }
            }
        }
    }
    
    // 设备
    if (node->has("devices")) {
        auto list = node->get("devices")->as_list();
        for (const auto& item : list) {
            cfg.devices.push_back(item->as_string());
        }
    }
    
    return cfg;
}

/**
 * @brief 从 YAML 加载 UserConfig
 */
inline UserConfig load_user_config(yaml::YamlNodePtr doc) {
    UserConfig config;
    
    if (!doc) return config;
    
    // 名称
    if (doc->has("name")) {
        config.name = doc->get("name")->as_string();
    }
    
    // Seccomp 配置
    if (doc->has("seccomp")) {
        auto sec = doc->get("seccomp");
        if (sec->has("enabled")) {
            config.use_seccomp = sec->get("enabled")->as_bool();
        }
        if (sec->has("kill_on_violation")) {
            config.seccomp_kill_on_violation = sec->get("kill_on_violation")->as_bool();
        }
        if (sec->has("allow")) {
            auto allow_list = sec->get("allow")->as_list();
            for (const auto& item : allow_list) {
                std::string name = item->as_string();
                int nr = syscall_name_to_nr(name);
                if (nr >= 0) {
                    config.allowed_syscalls.insert(nr);
                }
            }
        }
    }
    
    // Namespace 配置
    if (doc->has("namespace")) {
        auto ns = doc->get("namespace");
        if (ns->has("enabled")) {
            config.use_namespace = ns->get("enabled")->as_bool();
        }
        if (ns->has("mount")) config.ns_mount = ns->get("mount")->as_bool();
        if (ns->has("network")) config.ns_network = ns->get("network")->as_bool();
        if (ns->has("pid")) config.ns_pid = ns->get("pid")->as_bool();
        if (ns->has("ipc")) config.ns_ipc = ns->get("ipc")->as_bool();
        if (ns->has("uts")) config.ns_uts = ns->get("uts")->as_bool();
    }
    
    // Cgroup 配置
    if (doc->has("cgroup")) {
        auto cg = doc->get("cgroup");
        if (cg->has("enabled")) {
            config.use_cgroup = cg->get("enabled")->as_bool();
        }
        if (cg->has("memory_limit")) {
            config.memory_limit_bytes = cg->get("memory_limit")->as_int();
        }
        if (cg->has("cpu_time_limit")) {
            config.cpu_time_limit_us = cg->get("cpu_time_limit")->as_int();
        }
        if (cg->has("max_processes")) {
            config.max_processes = cg->get("max_processes")->as_int();
        }
    }
    
    // 沙箱配置（新的统一格式）
    if (doc->has("sandbox")) {
        config.sandbox = load_sandbox_config(doc->get("sandbox"));
    }
    
    // Rlimit 配置
    if (doc->has("rlimit")) {
        auto rl = doc->get("rlimit");
        if (rl->has("fsize")) config.rlimit_fsize = rl->get("fsize")->as_int();
        if (rl->has("as")) config.rlimit_as = rl->get("as")->as_int();
        if (rl->has("stack")) config.rlimit_stack = rl->get("stack")->as_int();
        if (rl->has("cpu")) config.rlimit_cpu = rl->get("cpu")->as_int();
        if (rl->has("nproc")) config.rlimit_nproc = rl->get("nproc")->as_int();
    }
    
    // 环境变量
    if (doc->has("env")) {
        auto env = doc->get("env");
        if (env->has("clear")) {
            config.clear_env = env->get("clear")->as_bool();
        }
        // TODO: 遍历环境变量 vars
    }
    
    return config;
}

// User::load 实现
inline UserPtr User::load(const std::string& yaml_path) {
    try {
        auto doc = yaml::load_yaml(yaml_path);
        if (!doc) return nullptr;
        
        UserConfig config = load_user_config(doc);
        return std::make_shared<User>(config);
    } catch (...) {
        return nullptr;
    }
}

// User::merge 实现
inline void User::merge(const UserConfig& other) {
    // 合并 syscall
    for (int nr : other.allowed_syscalls) {
        config_.allowed_syscalls.insert(nr);
    }
    
    // 合并沙箱路径
    for (const auto& p : other.sandbox.readonly) {
        config_.sandbox.readonly.push_back(p);
    }
    for (const auto& p : other.sandbox.writable) {
        config_.sandbox.writable.push_back(p);
    }
    for (const auto& [k, v] : other.sandbox.tmpfs) {
        config_.sandbox.tmpfs[k] = v;
    }
    for (const auto& d : other.sandbox.devices) {
        config_.sandbox.devices.push_back(d);
    }
    
    // 沙箱模式（用更严格的）
    if (other.sandbox.mode != SandboxMode::None) {
        config_.sandbox.mode = other.sandbox.mode;
    }
    
    // 如果 other 有更严格的限制，使用 other 的
    if (other.use_seccomp) config_.use_seccomp = true;
    if (other.use_namespace) config_.use_namespace = true;
    if (other.use_cgroup) config_.use_cgroup = true;
    
    // namespace 细项
    if (other.ns_network) config_.ns_network = true;
    if (other.ns_mount) config_.ns_mount = true;
    if (other.ns_pid) config_.ns_pid = true;
    if (other.ns_ipc) config_.ns_ipc = true;
    if (other.ns_uts) config_.ns_uts = true;
}

//=============================================================================
// 预定义 User 工厂方法
//=============================================================================

inline UserPtr User::system() {
    UserConfig config;
    config.name = "system";
    config.use_seccomp = false;
    config.use_namespace = false;
    config.use_cgroup = false;
    config.sandbox = FsSandboxConfig::none();
    return std::make_shared<User>(config);
}

inline UserPtr User::problem() {
    UserConfig config;
    config.name = "problem";
    config.use_seccomp = true;
    config.use_namespace = true;
    config.ns_mount = true;
    config.ns_network = true;
    config.ns_ipc = true;
    config.sandbox = FsSandboxConfig::runtime();
    
    // 允许的系统调用（checker/validator/interactor 需要的，没有 execve）
    const char* allowed[] = {
        "read", "write", "open", "close", "openat", "fstat", "lstat", "stat",
        "lseek", "mmap", "mprotect", "munmap", "brk", "exit", "exit_group",
        "getpid", "gettid", "futex", "set_tid_address", "set_robust_list",
        "prlimit64", "getrandom", "arch_prctl", "rt_sigaction", "rt_sigprocmask",
        "rt_sigreturn", "sigaltstack", "clock_gettime", "gettimeofday", "nanosleep",
        "access", "getcwd", "getdents64", "fcntl", "dup", "dup2", "pipe", "pipe2",
        "ioctl", "readv", "writev", "getuid", "geteuid", "getgid", "getegid",
        "uname", "sysinfo", nullptr
    };
    for (int i = 0; allowed[i]; ++i) {
        config.allowed_syscalls.insert(syscall_name_to_nr(allowed[i]));
    }
    
    return std::make_shared<User>(config);
}

inline UserPtr User::submission() {
    UserConfig config;
    config.name = "submission";
    config.use_seccomp = true;
    config.use_namespace = true;
    config.ns_mount = true;
    config.ns_network = true;
    config.ns_ipc = true;
    config.ns_uts = true;
    config.use_cgroup = true;
    config.sandbox = FsSandboxConfig::runtime();
    
    // 最小权限 syscall（注意：没有 execve）
    const char* allowed[] = {
        "read", "write", "open", "close", "openat", "fstat", "lseek", "access",
        "mmap", "mprotect", "munmap", "brk", "madvise",
        "exit", "exit_group", "getpid", "gettid",
        "futex", "set_tid_address", "set_robust_list",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack",
        "clock_gettime", "gettimeofday", "nanosleep",
        "arch_prctl", "prlimit64", "getrandom", "uname", nullptr
    };
    for (int i = 0; allowed[i]; ++i) {
        config.allowed_syscalls.insert(syscall_name_to_nr(allowed[i]));
    }
    
    return std::make_shared<User>(config);
}

inline UserPtr User::compiler() {
    UserConfig config;
    config.name = "compiler";
    config.use_seccomp = false;  // 编译器需要多种 syscall，不限制
    config.use_namespace = true;
    config.ns_mount = true;
    config.ns_network = true;
    config.ns_ipc = true;
    config.use_cgroup = true;
    config.sandbox = FsSandboxConfig::compiler();
    
    return std::make_shared<User>(config);
}

} // namespace uoj

#endif // UOJ_CORE_USER_LOADER_H
