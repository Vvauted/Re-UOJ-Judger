/**
 * @file user.h
 * @brief 统一的用户安全架构
 * 
 * 所有程序执行都通过 User 来管理安全限制，包括：
 * - seccomp 系统调用过滤
 * - namespace 隔离
 * - cgroup 资源限制
 * - 文件系统沙箱（pivot_root）
 */

#ifndef UOJ_CORE_USER_H
#define UOJ_CORE_USER_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <fstream>
#include <sstream>

#include "syscall_map.h"
#include "sandbox_config.h"

namespace uoj {

//=============================================================================
// User 安全配置
//=============================================================================

/**
 * @brief 用户安全配置
 * 
 * 定义一个用户（程序执行者）的所有安全限制
 */
struct UserConfig {
    std::string name;                    ///< 配置名称 (如 "system", "problem", "submission")
    
    //=========================================================================
    // Seccomp 配置
    //=========================================================================
    bool use_seccomp = true;             ///< 是否启用 seccomp
    std::set<int> allowed_syscalls;      ///< 允许的系统调用
    bool seccomp_kill_on_violation = true; ///< 违规时杀死进程（false = 返回 EPERM）
    
    //=========================================================================
    // Namespace 配置
    //=========================================================================
    bool use_namespace = false;          ///< 是否启用 namespace 隔离
    bool ns_mount = false;               ///< Mount namespace（文件系统隔离）
    bool ns_network = false;             ///< Network namespace（网络隔离）
    bool ns_pid = false;                 ///< PID namespace
    bool ns_ipc = false;                 ///< IPC namespace
    bool ns_uts = false;                 ///< UTS namespace（hostname 隔离）
    
    //=========================================================================
    // Cgroup 配置
    //=========================================================================
    bool use_cgroup = false;             ///< 是否使用 cgroup 限制
    int64_t memory_limit_bytes = 0;      ///< 内存限制（0 = 不限制）
    int64_t cpu_time_limit_us = 0;       ///< CPU 时间限制（微秒，0 = 不限制）
    int max_processes = 0;               ///< 最大进程数（0 = 不限制）
    
    //=========================================================================
    // 文件系统沙箱配置（统一结构）
    //=========================================================================
    FsSandboxConfig sandbox;             ///< 文件系统沙箱配置
    
    //=========================================================================
    // Rlimit 配置
    //=========================================================================
    int64_t rlimit_fsize = 0;            ///< 文件大小限制（0 = 不限制）
    int64_t rlimit_as = 0;               ///< 地址空间限制（-1 = 禁用）
    int64_t rlimit_stack = 0;            ///< 栈大小限制
    int64_t rlimit_cpu = 0;              ///< CPU 时间限制（秒）
    int64_t rlimit_nproc = 0;            ///< 进程数限制
    
    //=========================================================================
    // 环境变量
    //=========================================================================
    std::map<std::string, std::string> env;  ///< 环境变量
    bool clear_env = true;               ///< 是否清除原有环境变量
    
    //=========================================================================
    // 其他
    //=========================================================================
    std::string work_dir;                ///< 工作目录
    bool chdir_to_work = true;           ///< 是否 chdir 到工作目录
};

//=============================================================================
// User 类 - 管理程序执行的安全上下文
//=============================================================================

class User;
using UserPtr = std::shared_ptr<User>;

/**
 * @brief User 类 - 统一的安全执行上下文
 * 
 * 用法:
 *   auto user = User::load("config/users/submission.yml");
 *   user->run("./program", {"arg1", "arg2"}, limits);
 */
class User {
private:
    UserConfig config_;
    
public:
    explicit User(const UserConfig& config) : config_(config) {}
    
    // 获取配置
    const UserConfig& config() const { return config_; }
    UserConfig& config() { return config_; }
    const std::string& name() const { return config_.name; }
    
    /**
     * @brief 从 YAML 文件加载 User 配置
     */
    static UserPtr load(const std::string& yaml_path);
    
    /**
     * @brief 获取预定义的 User
     */
    static UserPtr system();      // 系统级权限（judger 主进程）
    static UserPtr problem();     // 题目级权限（checker, validator, interactor）
    static UserPtr submission();  // 提交级权限（用户程序）
    static UserPtr compiler();    // 编译器权限
    
    /**
     * @brief 合并另一个 User 的配置（用于语言特定覆盖）
     */
    void merge(const UserConfig& other);
    
    /**
     * @brief 添加允许的系统调用
     */
    void allow_syscall(int nr) { config_.allowed_syscalls.insert(nr); }
    void allow_syscall(const std::string& name) {
        int nr = syscall_name_to_nr(name);
        if (nr >= 0) config_.allowed_syscalls.insert(nr);
    }
    
    /**
     * @brief 添加沙箱路径
     */
    void add_readonly(const std::string& path) { config_.sandbox.readonly.push_back(path); }
    void add_writable(const std::string& path) { config_.sandbox.writable.push_back(path); }
};

//=============================================================================
// UserRegistry - 全局 User 注册表
//=============================================================================

class UserRegistry {
private:
    std::map<std::string, UserPtr> users_;
    std::string config_dir_;
    
    UserRegistry() = default;
    
public:
    static UserRegistry& instance() {
        static UserRegistry inst;
        return inst;
    }
    
    void set_config_dir(const std::string& dir) { config_dir_ = dir; }
    
    /**
     * @brief 获取或加载 User
     */
    UserPtr get(const std::string& name) {
        auto it = users_.find(name);
        if (it != users_.end()) return it->second;
        
        // 尝试加载
        std::string path = config_dir_ + "/users/" + name + ".yml";
        auto user = User::load(path);
        if (user) {
            users_[name] = user;
        }
        return user;
    }
    
    /**
     * @brief 注册预定义 User
     */
    void register_user(const std::string& name, UserPtr user) {
        users_[name] = user;
    }
};

} // namespace uoj

#endif // UOJ_CORE_USER_H
