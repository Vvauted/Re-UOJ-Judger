/**
 * @file sandbox_config.h
 * @brief 统一的沙箱配置结构
 * 
 * 所有文件系统隔离配置都在这里定义，简洁统一：
 * 
 * sandbox:
 *   mode: pivot_root   # pivot_root | bind | none
 *   readonly:
 *     - /opt/uoj/runtime
 *   writable:
 *     - "{work_dir}"
 *   tmpfs:
 *     /tmp: 16m
 *     /dev: 4m
 *   devices:
 *     - /dev/null
 *     - /dev/urandom
 */

#ifndef UOJ_CORE_SANDBOX_CONFIG_H
#define UOJ_CORE_SANDBOX_CONFIG_H

#include <string>
#include <vector>
#include <map>

namespace uoj {

/**
 * @brief 沙箱模式
 */
enum class SandboxMode {
    None,        ///< 不做隔离（system 权限）
    PivotRoot    ///< 使用 pivot_root 创建全新根（最安全）
};

inline SandboxMode parse_sandbox_mode(const std::string& s) {
    if (s == "pivot_root") return SandboxMode::PivotRoot;
    if (s == "none" || s == "full") return SandboxMode::None;
    return SandboxMode::PivotRoot;  // 默认最安全
}

inline const char* sandbox_mode_to_string(SandboxMode mode) {
    switch (mode) {
        case SandboxMode::None: return "none";
        case SandboxMode::PivotRoot: return "pivot_root";
    }
    return "pivot_root";
}

/**
 * @brief 统一的文件系统沙箱配置
 */
struct FsSandboxConfig {
    SandboxMode mode = SandboxMode::PivotRoot;
    
    /// 只读挂载路径（白名单）
    std::vector<std::string> readonly;
    
    /// 可写挂载路径
    std::vector<std::string> writable;
    
    /// tmpfs 挂载（路径 -> 大小）
    std::map<std::string, std::string> tmpfs;
    
    /// 设备节点
    std::vector<std::string> devices;
    
    /**
     * @brief 添加只读路径
     */
    FsSandboxConfig& add_readonly(const std::string& path) {
        readonly.push_back(path);
        return *this;
    }
    
    /**
     * @brief 添加可写路径
     */
    FsSandboxConfig& add_writable(const std::string& path) {
        writable.push_back(path);
        return *this;
    }
    
    /**
     * @brief 添加 tmpfs
     */
    FsSandboxConfig& add_tmpfs(const std::string& path, const std::string& size = "16m") {
        tmpfs[path] = size;
        return *this;
    }
    
    /**
     * @brief 添加设备
     */
    FsSandboxConfig& add_device(const std::string& dev) {
        devices.push_back(dev);
        return *this;
    }
    
    /**
     * @brief 默认运行时配置
     */
    static FsSandboxConfig runtime() {
        FsSandboxConfig cfg;
        cfg.mode = SandboxMode::PivotRoot;
        
        // 运行时库（只读）
        cfg.readonly = {
            "/opt/uoj/runtime",  // 统一的运行时目录
            "/lib",
            "/lib64",
            "/usr/lib"
        };
        
        // tmpfs
        cfg.tmpfs = {
            {"/tmp", "16m"},
            {"/dev", "4m"}
        };
        
        // 设备
        cfg.devices = {
            "/dev/null",
            "/dev/urandom",
            "/dev/zero"
        };
        
        return cfg;
    }
    
    /**
     * @brief 编译器配置
     */
    static FsSandboxConfig compiler() {
        FsSandboxConfig cfg;
        cfg.mode = SandboxMode::PivotRoot;
        
        // 编译器需要更多路径
        cfg.readonly = {
            "/opt/uoj/compiler",  // 编译器
            "/opt/uoj/runtime",   // 运行时库
            "/lib",
            "/lib64",
            "/usr/lib",
            "/usr/include"        // 头文件
        };
        
        cfg.tmpfs = {
            {"/tmp", "64m"},
            {"/dev", "4m"}
        };
        
        cfg.devices = {
            "/dev/null",
            "/dev/urandom",
            "/dev/zero"
        };
        
        return cfg;
    }
    
    /**
     * @brief 无限制配置
     */
    static FsSandboxConfig none() {
        FsSandboxConfig cfg;
        cfg.mode = SandboxMode::None;
        return cfg;
    }
};

} // namespace uoj

#endif // UOJ_CORE_SANDBOX_CONFIG_H

