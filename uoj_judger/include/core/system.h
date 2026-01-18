/**
 * @file system.h
 * @brief 系统命令执行器
 * 
 * 用法：
 *   // 加载配置
 *   auto compiler = Sys::load("config/users/compiler.yml");
 *   auto runner = Sys::load("config/users/submission.yml");
 *   
 *   // 执行
 *   compiler.work_dir(x).limit(l).exec(prog, args);
 *   runner.stdin_file(in).stdout_file(out).exec(prog, args);
 *   
 *   // 预加载的（启动时初始化）
 *   Sys::get("system").exec(...);
 *   Sys::get("problem").exec(...);
 */

#ifndef UOJ_CORE_SYSTEM_H
#define UOJ_CORE_SYSTEM_H

#include <string>
#include <vector>
#include <map>
#include <memory>

#include "user.h"
#include "user_loader.h"
#include "types.h"
#include "sandbox/sandbox.h"

namespace uoj {

/**
 * @brief 执行结果
 */
struct ExecResult {
    bool ok = false;
    int exit_code = -1;
    int time_ms = 0;
    int memory_kb = 0;
    sandbox::RunStatus status = sandbox::RunStatus::INTERNAL_ERROR;
    std::string error;
    
    RunResult to_run_result() const {
        RunResult r;
        r.ust = time_ms;
        r.usm = memory_kb;
        r.exit_code = exit_code;
        
        switch (status) {
            case sandbox::RunStatus::OK:
                r.type = (exit_code == 0) ? RS_AC : RS_RE; break;
            case sandbox::RunStatus::TIME_LIMIT:
                r.type = RS_TLE; break;
            case sandbox::RunStatus::MEMORY_LIMIT:
                r.type = RS_MLE; break;
            case sandbox::RunStatus::OUTPUT_LIMIT:
                r.type = RS_OLE; break;
            case sandbox::RunStatus::SECCOMP_VIOLATION:
                r.type = RS_DGS; break;
            case sandbox::RunStatus::RUNTIME_ERROR:
            case sandbox::RunStatus::KILLED_BY_SIGNAL:
                r.type = RS_RE; break;
            default:
                r.type = RS_JGF;
        }
        return r;
    }
};

/**
 * @brief 系统执行器
 */
class Sys {
private:
    UserConfig config_;
    
    // 执行参数
    int time_ms_ = 0;
    int memory_kb_ = 0;
    int output_kb_ = 0;
    std::string work_dir_;
    std::string stdin_ = "/dev/null";
    std::string stdout_ = "/dev/null";
    std::string stderr_ = "/dev/null";
    std::vector<std::pair<std::string, std::string>> env_;
    
    // 全局缓存
    static inline std::map<std::string, Sys> cache_;
    static inline std::string config_dir_;

public:
    Sys() = default;
    explicit Sys(const UserConfig& cfg) : config_(cfg) {}
    explicit Sys(UserPtr user) : config_(user->config()) {}
    
    //=========================================================================
    // 加载
    //=========================================================================
    
    static Sys load(const std::string& path) {
        auto user = User::load(path);
        return user ? Sys(user) : Sys();
    }
    
    static Sys& get(const std::string& name) {
        auto it = cache_.find(name);
        if (it != cache_.end()) {
            return it->second;
        }
        
        // 尝试自动加载配置文件
        std::string path = config_dir_ + "/users/" + name + ".yml";
        if (access(path.c_str(), F_OK) == 0) {
            preload(name, path);
            return cache_[name];
        }
        
        static Sys empty;
        return empty;
    }
    
    static void preload(const std::string& name, const std::string& path) {
        cache_[name] = load(path);
    }
    
    static void preload(const std::string& name, UserPtr user) {
        if (user) cache_[name] = Sys(user);
    }
    
    static void init() {
        preload("system", User::system());
        preload("problem", User::problem());
        preload("submission", User::submission());
        preload("compiler", User::compiler());
    }
    
    static void init(const std::string& config_dir) {
        config_dir_ = config_dir;
        init();
        
        std::vector<std::string> names = {"system", "problem", "submission", "compiler"};
        for (const auto& name : names) {
            std::string path = config_dir + "/users/" + name + ".yml";
            if (access(path.c_str(), F_OK) == 0) {
                preload(name, path);
            }
        }
    }
    
    //=========================================================================
    // 链式配置
    //=========================================================================
    
    Sys time_limit(int ms) const { Sys s = *this; s.time_ms_ = ms; return s; }
    Sys memory_limit(int kb) const { Sys s = *this; s.memory_kb_ = kb; return s; }
    Sys output_limit(int kb) const { Sys s = *this; s.output_kb_ = kb; return s; }
    Sys work_dir(const std::string& d) const { Sys s = *this; s.work_dir_ = d; return s; }
    Sys stdin_file(const std::string& f) const { Sys s = *this; s.stdin_ = f; return s; }
    Sys stdout_file(const std::string& f) const { Sys s = *this; s.stdout_ = f; return s; }
    Sys stderr_file(const std::string& f) const { Sys s = *this; s.stderr_ = f; return s; }
    
    Sys env(const std::string& k, const std::string& v) const { 
        Sys s = *this; 
        s.env_.push_back({k, v}); 
        return s; 
    }
    
    Sys limit(const RunLimit& lim) const {
        Sys s = *this;
        s.time_ms_ = lim.time * 1000;
        s.memory_kb_ = lim.memory * 1024;
        s.output_kb_ = lim.output * 1024;
        return s;
    }
    
    /**
     * @brief 添加只读路径
     */
    Sys add_readonly(const std::string& path) const {
        Sys s = *this;
        s.config_.sandbox.readonly.push_back(path);
        return s;
    }
    
    /**
     * @brief 添加可写路径
     */
    Sys add_writable(const std::string& path) const {
        Sys s = *this;
        s.config_.sandbox.writable.push_back(path);
        return s;
    }
    
    //=========================================================================
    // 执行
    //=========================================================================
    
    ExecResult exec(const std::string& program, 
                    const std::vector<std::string>& args = {}) const {
        sandbox::SandboxConfig cfg = sandbox::SandboxConfig::from_user(config_);
        
        cfg.program = program;
        cfg.args = args;
        
        if (time_ms_ > 0) cfg.time_limit_ms = time_ms_;
        if (memory_kb_ > 0) cfg.memory_limit_kb = memory_kb_;
        if (output_kb_ > 0) cfg.output_limit_kb = output_kb_;
        
        if (!work_dir_.empty()) {
            cfg.work_dir = work_dir_;
            // 工作目录自动添加到可写列表
            cfg.sandbox.writable.push_back(work_dir_);
        }
        
        cfg.stdin_file = stdin_;
        cfg.stdout_file = stdout_;
        cfg.stderr_file = stderr_;
        
        // 添加 stderr 文件所在目录到可写列表（编译器输出错误信息）
        if (!stderr_.empty() && stderr_ != "/dev/null") {
            size_t pos = stderr_.rfind('/');
            if (pos != std::string::npos) {
                std::string stderr_dir = stderr_.substr(0, pos);
                cfg.sandbox.writable.push_back(stderr_dir);
            }
        }
        
        for (const auto& [k, v] : env_) {
            cfg.env.push_back(k + "=" + v);
        }
        
        // 只有当用户配置启用 cgroup 且系统支持时才使用
        cfg.use_cgroup = cfg.use_cgroup && sandbox::is_cgroup_v2_available();
        
        sandbox::Sandbox sb(cfg);
        auto result = sb.run();
        
        ExecResult res;
        if (!result.ok()) {
            res.error = result.error().message();
            return res;
        }
        
        const auto& sr = result.value();
        res.ok = true;
        res.exit_code = sr.exit_code;
        res.time_ms = sr.time_ms;
        res.memory_kb = sr.memory_kb;
        res.status = sr.status;
        return res;
    }
    
    ExecResult operator()(const std::string& prog, 
                          const std::vector<std::string>& args = {}) const {
        return exec(prog, args);
    }
};

} // namespace uoj

#endif // UOJ_CORE_SYSTEM_H
