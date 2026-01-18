/**
 * @file language.h
 * @brief 语言插件系统
 * 
 * 定义语言插件接口和注册机制，支持动态添加新语言
 */

#ifndef UOJ_CORE_LANGUAGE_H
#define UOJ_CORE_LANGUAGE_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include "core/types.h"
#include "core/syscall_policy.h"

namespace uoj {

// 前向声明
class Config;

/**
 * @brief 编译上下文
 * 
 * 包含编译所需的所有信息
 */
struct CompileContext {
    std::string main_path;      ///< 主路径
    std::string work_path;      ///< 工作目录
    std::string result_path;    ///< 结果目录
    std::string data_path;      ///< 数据目录
    std::string name;           ///< 程序名（如 "answer"）
    std::string source_file;    ///< 源文件路径
    Config* config;             ///< 配置对象
    
    /// 便捷方法：获取完整源文件路径
    std::string get_source_path() const {
        return work_path + "/" + name + ".code";
    }
};

/**
 * @brief 运行上下文
 * 
 * 包含运行程序所需的配置
 */
struct RunContext {
    std::string work_path;      ///< 工作目录
    std::string name;           ///< 程序名
    Config* config;             ///< 配置对象
};

/**
 * @brief 语言插件接口
 * 
 * 所有语言插件必须实现此接口
 */
class LanguagePlugin {
public:
    virtual ~LanguagePlugin() = default;

    //==========================================================================
    // 基本信息
    //==========================================================================
    
    /// 语言标识符（如 "C++", "Python3", "Lean4.23.0"）
    virtual std::string id() const = 0;
    
    /// 语言显示名称
    virtual std::string display_name() const = 0;
    
    /// 语言版本
    virtual std::string version() const { return ""; }
    
    /// 语言描述
    virtual std::string description() const { return ""; }
    
    /// 文件扩展名
    virtual std::vector<std::string> file_extensions() const = 0;

    //==========================================================================
    // 编译相关
    //==========================================================================
    
    /// 是否需要编译
    virtual bool needs_compile() const { return true; }
    
    /// 是否禁止某些关键字（如 asm）
    virtual bool check_illegal_keywords() const { return false; }
    
    /// 非法关键字列表
    virtual std::vector<std::string> illegal_keywords() const { return {}; }
    
    /// 编译程序
    virtual RunCompilerResult compile(const CompileContext &ctx) = 0;
    
    /// 带 implementer 编译（可选）
    virtual RunCompilerResult compile_with_implementer(const CompileContext &ctx) {
        RunCompilerResult res;
        res.succeeded = false;
        res.info = "This language does not support implementer mode.";
        return res;
    }

    //==========================================================================
    // 运行相关
    //==========================================================================
    
    /// 沙箱类型（如 "default", "python3", "java8", "lean"）
    virtual std::string sandbox_type() const { return "default"; }
    
    /// 获取可执行文件路径
    virtual std::string get_executable(const RunContext &ctx) const {
        return ctx.work_path + "/" + ctx.name;  // 返回完整路径
    }
    
    /// 获取运行命令参数
    virtual std::vector<std::string> get_run_args(const RunContext &ctx) const {
        return { get_executable(ctx) };
    }
    
    /// 获取运行时 Syscall 策略
    virtual SyscallPolicy get_runtime_policy() const {
        return get_base_syscall_policy();
    }
    
    /// 获取编译器 Syscall 策略
    virtual SyscallPolicy get_compiler_policy() const {
        return get_compiler_base_policy();
    }
    
    /// 是否需要 main_class（Java 等语言）
    virtual bool needs_main_class() const { return false; }
    
    /// 获取默认 main_class
    virtual std::string get_default_main_class() const { return "Main"; }

    //==========================================================================
    // 资源限制
    //==========================================================================
    
    /// 时间限制乘数（解释型语言通常需要更多时间）
    virtual double time_multiplier() const { return 1.0; }
    
    /// 内存限制乘数（JVM/解释器需要额外内存）
    virtual double memory_multiplier() const { return 1.0; }
    
    /// 额外的基础内存（解释器/运行时本身占用的内存，单位 MB）
    virtual int base_memory_mb() const { return 0; }
    
    /// 默认编译时间限制（秒）
    virtual int default_compile_time_limit() const { return 15; }
    
    /// 默认编译内存限制（MB）
    virtual int default_compile_memory_limit() const { return 512; }
    
    /// 调整运行时资源限制
    virtual RunLimit adjust_run_limit(const RunLimit& original) const {
        return RunLimit(
            static_cast<int>(original.time * time_multiplier()),
            static_cast<int>(original.memory * memory_multiplier() + base_memory_mb()),
            original.output
        );
    }
    
    /// 获取编译器资源限制
    virtual RunLimit get_compiler_limit() const {
        return RunLimit(default_compile_time_limit(), default_compile_memory_limit(), 64);
    }

    //==========================================================================
    // 环境变量
    //==========================================================================
    
    /// 获取运行时需要的环境变量
    virtual std::map<std::string, std::string> get_runtime_env() const {
        return {};
    }
    
    /// 获取编译时需要的环境变量
    virtual std::map<std::string, std::string> get_compile_env() const {
        return {};
    }

    //==========================================================================
    // 编译器类型
    //==========================================================================
    
    /// 编译器沙箱类型
    virtual std::string compiler_sandbox_type() const { return "compiler"; }
    
    /// 获取编译器命令
    virtual std::string get_compiler_command() const { return "/usr/bin/g++"; }
    
    /// 获取编译器参数
    virtual std::vector<std::string> get_compiler_args() const {
        return {"-o", "{output}", "{source}", "-O2", "-lm", "-DONLINE_JUDGE"};
    }
    
    //==========================================================================
    // 输出处理
    //==========================================================================
    
    /// 是否需要特殊的输出处理（如去除末尾空白）
    virtual bool needs_output_postprocess() const { return false; }
    
    /// 输出后处理
    virtual std::string postprocess_output(const std::string& output) const {
        return output;
    }
};

/**
 * @brief 语言注册表
 * 
 * 管理所有注册的语言插件
 */
class LanguageRegistry {
private:
    std::map<std::string, std::shared_ptr<LanguagePlugin>> plugins_;
    static LanguageRegistry* instance_;
    
    LanguageRegistry() = default;

public:
    /// 获取单例实例
    static LanguageRegistry& instance() {
        if (!instance_) {
            instance_ = new LanguageRegistry();
        }
        return *instance_;
    }
    
    /// 注册语言插件
    void register_plugin(std::shared_ptr<LanguagePlugin> plugin) {
        plugins_[plugin->id()] = plugin;
    }
    
    /// 注册语言插件（便捷模板）
    template<typename T, typename... Args>
    void register_language(Args&&... args) {
        auto plugin = std::make_shared<T>(std::forward<Args>(args)...);
        register_plugin(plugin);
    }
    
    /// 获取语言插件
    LanguagePlugin* get(const std::string &id) const {
        auto it = plugins_.find(id);
        return (it != plugins_.end()) ? it->second.get() : nullptr;
    }
    
    /// 检查语言是否已注册
    bool has(const std::string &id) const {
        return plugins_.find(id) != plugins_.end();
    }
    
    /// 获取所有已注册语言的 ID
    std::vector<std::string> list() const {
        std::vector<std::string> result;
        for (const auto &kv : plugins_) {
            result.push_back(kv.first);
        }
        return result;
    }
    
    /// 获取插件数量
    size_t count() const {
        return plugins_.size();
    }
};

// 静态成员初始化
inline LanguageRegistry* LanguageRegistry::instance_ = nullptr;

/**
 * @brief 语言注册宏
 * 
 * 使用方式：
 * REGISTER_LANGUAGE(CppLanguage);
 */
#define REGISTER_LANGUAGE(PluginClass) \
    namespace { \
        struct PluginClass##Registrar { \
            PluginClass##Registrar() { \
                uoj::LanguageRegistry::instance().register_language<PluginClass>(); \
            } \
        } g_##PluginClass##Registrar; \
    }

} // namespace uoj

#endif // UOJ_CORE_LANGUAGE_H

