/**
 * @file language_loader.h
 * @brief 从 YAML 文件加载语言配置
 * 
 * 所有语言配置从 YAML 加载，不再硬编码
 */

#ifndef UOJ_CORE_LANGUAGE_LOADER_H
#define UOJ_CORE_LANGUAGE_LOADER_H

#include "language.h"
#include "yaml_config.h"
#include "syscall_policy.h"
#include "syscall_map.h"  // 统一的 syscall 名称映射
#include "compiler.h"
#include "runner.h"
#include <iostream>
#include <filesystem>

namespace uoj {

/**
 * @brief YAML 配置驱动的语言插件
 * 
 * 从 YAML 文件加载语言配置，而不是硬编码
 */
class YamlLanguagePlugin : public LanguagePlugin {
private:
    yaml::YamlNodePtr config_;
    std::string id_;
    std::string display_name_;
    std::string version_;
    std::string description_;
    std::vector<std::string> extensions_;
    bool needs_compile_;
    bool check_keywords_;
    std::vector<std::string> illegal_keywords_;
    
    // 编译配置
    std::string compiler_command_;
    std::vector<std::string> compiler_args_;
    int compile_time_limit_;
    int compile_memory_limit_;
    int compile_output_limit_;
    std::string compiler_sandbox_type_;
    std::string compiler_work_dir_;
    
    // 运行配置
    std::string runtime_command_;
    std::vector<std::string> runtime_args_;
    std::string runtime_sandbox_type_;
    std::string runtime_executable_;
    double time_multiplier_;
    double memory_multiplier_;
    int base_memory_;
    int runtime_max_processes_ = 1;
    
    // 环境变量
    std::map<std::string, std::string> compile_env_;
    std::map<std::string, std::string> runtime_env_;
    
    // Syscall 配置缓存
    mutable SyscallPolicy runtime_policy_;
    mutable SyscallPolicy compiler_policy_;
    mutable bool policies_loaded_ = false;
    
    // 语言特性标志
    bool is_java_ = false;
    std::string java_home_;
    bool needs_main_class_ = false;
    std::string default_main_class_ = "Main";
    
    void load_policies() const {
        if (policies_loaded_) return;
        
        runtime_policy_ = get_base_syscall_policy();
        compiler_policy_ = get_compiler_base_policy();
        
        // 加载运行时 syscall 配置
        if (auto syscall = config_->get("syscall")) {
            if (auto runtime = syscall->get("runtime")) {
                load_syscall_config(runtime, runtime_policy_);
            }
            if (auto compiler = syscall->get("compiler")) {
                load_syscall_config(compiler, compiler_policy_);
            }
        }
        
        policies_loaded_ = true;
    }
    
    void load_syscall_config(yaml::YamlNodePtr node, SyscallPolicy& policy) const {
        // 加载允许的 syscall
        if (auto allow = node->get("allow")) {
            if (allow->is_list()) {
                for (const auto& item : allow->as_list()) {
                    if (item->is_map()) {
                        for (const auto& [name, val] : item->as_map()) {
                            int nr = syscall_name_to_nr(name);
                            if (nr >= 0) {
                                policy.allow(nr, static_cast<int>(val->as_int(-1)));
                            }
                        }
                    }
                }
            }
        }
        
        // 加载软禁止的 syscall
        if (auto soft_ban = node->get("soft_ban")) {
            for (const auto& name : soft_ban->as_string_list()) {
                int nr = syscall_name_to_nr(name);
                if (nr >= 0) {
                    policy.soft_ban(nr);
                }
            }
        }
        
        // 加载可读路径
        if (auto readable = node->get("readable_paths")) {
            for (const auto& path : readable->as_string_list()) {
                policy.read(path);
            }
        }
        
        // 加载可写路径
        if (auto writable = node->get("writable_paths")) {
            for (const auto& path : writable->as_string_list()) {
                policy.write(path);
            }
        }
        
        // 加载可执行路径
        if (auto executable = node->get("execute_paths")) {
            for (const auto& path : executable->as_string_list()) {
                policy.execute_paths.push_back(path);
            }
        }
        
        // 加载标志
        if (auto allow_clone = node->get("allow_clone")) {
            policy.allow_clone = allow_clone->as_bool();
        }
        if (auto allow_exec = node->get("allow_exec")) {
            policy.allow_exec = allow_exec->as_bool();
        }
        if (auto use_namespace = node->get("use_namespace")) {
            policy.use_namespace = use_namespace->as_bool();
        }
        if (auto use_landlock = node->get("use_landlock")) {
            policy.use_landlock = use_landlock->as_bool();
        }
        if (auto use_ptrace = node->get("use_ptrace")) {
            policy.use_ptrace = use_ptrace->as_bool();
        }
        if (auto max_procs = node->get("max_processes")) {
            policy.max_processes = static_cast<int>(max_procs->as_int());
        }
        if (auto stack = node->get("stack_limit_mb")) {
            policy.stack_limit_mb = static_cast<int>(stack->as_int());
        }
        if (auto disable_as = node->get("disable_address_limit")) {
            policy.disable_address_limit = disable_as->as_bool();
        }
    }
    
    // syscall_name_to_nr 已移至 syscall_map.h（统一管理）

public:
    explicit YamlLanguagePlugin(yaml::YamlNodePtr config) : config_(config) {
        // 加载基本信息
        auto lang = config_->get("language");
        id_ = (*lang)["id"]->as_string();
        display_name_ = lang->get("display_name")->as_string(id_);
        version_ = lang->has("version") ? lang->get("version")->as_string() : "";
        description_ = lang->has("description") ? lang->get("description")->as_string() : "";
        extensions_ = lang->get("extensions")->as_string_list();
        needs_compile_ = lang->has("needs_compile") ? lang->get("needs_compile")->as_bool() : true;
        check_keywords_ = lang->has("check_illegal_keywords") ? lang->get("check_illegal_keywords")->as_bool() : false;
        if (check_keywords_ && lang->has("illegal_keywords")) {
            illegal_keywords_ = lang->get("illegal_keywords")->as_string_list();
        }
        
        // 从配置读取是否需要 main_class（Java 等语言需要）
        needs_main_class_ = lang->has("needs_main_class") ? lang->get("needs_main_class")->as_bool() : false;
        default_main_class_ = lang->has("default_main_class") ? lang->get("default_main_class")->as_string() : "Main";
        
        // 兼容：检测是否是 Java（用于 JAVA_HOME 等）
        is_java_ = (id_.find("Java") != std::string::npos);
        
        // 加载编译配置
        if (auto compiler = config_->get("compiler")) {
            compiler_command_ = compiler->get("command")->as_string();
            if (compiler->has("args")) {
                compiler_args_ = compiler->get("args")->as_string_list();
            }
            compile_time_limit_ = compiler->has("time_limit") ? static_cast<int>(compiler->get("time_limit")->as_int()) : 15;
            compile_memory_limit_ = compiler->has("memory_limit") ? static_cast<int>(compiler->get("memory_limit")->as_int()) : 512;
            compile_output_limit_ = compiler->has("output_limit") ? static_cast<int>(compiler->get("output_limit")->as_int()) : 256;
            compiler_sandbox_type_ = compiler->has("sandbox_type") ? compiler->get("sandbox_type")->as_string() : "compiler";
            compiler_work_dir_ = compiler->has("work_dir") ? compiler->get("work_dir")->as_string() : "";
        }
        
        // 加载运行配置
        if (auto runtime = config_->get("runtime")) {
            runtime_command_ = runtime->has("command") ? runtime->get("command")->as_string() : "";
            if (runtime->has("args")) {
                runtime_args_ = runtime->get("args")->as_string_list();
            }
            runtime_sandbox_type_ = runtime->has("sandbox_type") ? runtime->get("sandbox_type")->as_string() : "default";
            runtime_executable_ = runtime->has("executable") ? runtime->get("executable")->as_string() : "";
            time_multiplier_ = runtime->has("time_multiplier") ? runtime->get("time_multiplier")->as_double() : 1.0;
            memory_multiplier_ = runtime->has("memory_multiplier") ? runtime->get("memory_multiplier")->as_double() : 1.0;
            base_memory_ = runtime->has("base_memory") ? static_cast<int>(runtime->get("base_memory")->as_int()) : 0;
            runtime_max_processes_ = runtime->has("max_processes") ? static_cast<int>(runtime->get("max_processes")->as_int()) : 1;
        }
        
        // 加载环境变量
        if (auto env = config_->get("env")) {
            if (auto compile = env->get("compile")) {
                for (const auto& [k, v] : compile->as_map()) {
                    compile_env_[k] = v->as_string();
                    if (k == "JAVA_HOME") {
                        java_home_ = v->as_string();
                    }
                }
            }
            if (auto runtime = env->get("runtime")) {
                for (const auto& [k, v] : runtime->as_map()) {
                    runtime_env_[k] = v->as_string();
                }
            }
        }
    }
    
    // LanguagePlugin 接口实现
    std::string id() const override { return id_; }
    std::string display_name() const override { return display_name_; }
    std::string version() const override { return version_; }
    std::string description() const override { return description_; }
    std::vector<std::string> file_extensions() const override { return extensions_; }
    bool needs_compile() const override { return needs_compile_; }
    bool check_illegal_keywords() const override { return check_keywords_; }
    std::vector<std::string> illegal_keywords() const override { return illegal_keywords_; }
    
    std::string sandbox_type() const override { return runtime_sandbox_type_; }
    std::string compiler_sandbox_type() const override { return compiler_sandbox_type_; }
    
    double time_multiplier() const override { return time_multiplier_; }
    double memory_multiplier() const override { return memory_multiplier_; }
    int base_memory_mb() const override { return base_memory_; }
    int default_compile_time_limit() const override { return compile_time_limit_; }
    int default_compile_memory_limit() const override { return compile_memory_limit_; }
    
    std::map<std::string, std::string> get_compile_env() const override { return compile_env_; }
    std::map<std::string, std::string> get_runtime_env() const override { return runtime_env_; }
    
    SyscallPolicy get_runtime_policy() const override {
        load_policies();
        runtime_policy_.max_processes = runtime_max_processes_;
        return runtime_policy_;
    }
    
    SyscallPolicy get_compiler_policy() const override {
        load_policies();
        return compiler_policy_;
    }
    
    // 获取编译命令（覆写基类虚函数）
    std::string get_compiler_command() const override { return compiler_command_; }
    std::vector<std::string> get_compiler_args() const override { return compiler_args_; }
    std::string get_compiler_work_dir() const { return compiler_work_dir_; }
    
    // 获取编译器资源限制（覆写基类虚函数）
    RunLimit get_compiler_limit() const override {
        RunLimit limit;
        limit.time = compile_time_limit_;
        limit.memory = compile_memory_limit_;
        limit.output = compile_output_limit_;
        return limit;
    }
    
    // 获取运行命令和参数
    std::string get_runtime_command() const { return runtime_command_; }
    std::vector<std::string> get_runtime_args() const { return runtime_args_; }
    std::string get_runtime_executable() const { return runtime_executable_; }
    
    // 是否是 Java 语言
    bool is_java() const { return is_java_; }
    std::string get_java_home() const { return java_home_; }
    
    // 是否需要 main_class（Java 等语言）
    bool needs_main_class() const override { return needs_main_class_; }
    std::string get_default_main_class() const override { return default_main_class_; }
    
    // 替换占位符
    std::string replace_placeholders(const std::string& str, const std::map<std::string, std::string>& vars) const {
        std::string result = str;
        for (const auto& [key, value] : vars) {
            std::string placeholder = "{" + key + "}";
            size_t pos;
            while ((pos = result.find(placeholder)) != std::string::npos) {
                result.replace(pos, placeholder.length(), value);
            }
        }
        return result;
    }
    
    // 构建编译命令参数列表
    std::vector<std::string> build_compile_args(const std::string& source, const std::string& output,
                                                 const std::string& work_path = "") const {
        std::map<std::string, std::string> vars = {
            {"source", source},
            {"output", output},
            {"work_path", work_path}
        };
        
        std::vector<std::string> args;
        args.push_back(compiler_command_);
        for (const auto& arg : compiler_args_) {
            args.push_back(replace_placeholders(arg, vars));
        }
        return args;
    }
    
    // 构建运行命令参数列表
    std::vector<std::string> build_run_args(const std::string& program, const std::string& work_path = "",
                                            const std::string& main_class = "") const {
        std::map<std::string, std::string> vars = {
            {"program", program},
            {"work_path", work_path},
            {"main_class", main_class}
        };
        
        std::vector<std::string> args;
        
        if (runtime_command_.empty()) {
            // 编译型语言直接运行可执行文件
            std::string exe;
            if (!runtime_executable_.empty()) {
                exe = runtime_executable_;
            } else {
                exe = program;
            }
            // 确保使用完整路径
            if (!exe.empty() && exe[0] != '/' && !work_path.empty()) {
                exe = work_path + "/" + exe;
            }
            args.push_back(exe);
        } else {
            args.push_back(runtime_command_);
            for (const auto& arg : runtime_args_) {
                args.push_back(replace_placeholders(arg, vars));
            }
        }
        return args;
    }
    
    // 获取可执行文件路径
    std::string get_executable(const RunContext &ctx) const override {
        if (!runtime_executable_.empty()) {
            // 如果是绝对路径，直接返回；否则加上工作目录
            if (runtime_executable_[0] == '/') {
                return runtime_executable_;
            }
            return ctx.work_path + "/" + runtime_executable_;
        }
        return ctx.work_path + "/" + ctx.name;  // 返回完整路径
    }
    
    // 获取运行命令参数
    std::vector<std::string> get_run_args(const RunContext &ctx) const override {
        std::string main_class;
        if (is_java_) {
            main_class = ctx.config->get_str(ctx.name + "_main_class");
        }
        return build_run_args(ctx.name, ctx.work_path, main_class);
    }
    
    // 编译实现（由 Compiler 类调用）
    RunCompilerResult compile(const CompileContext& ctx) override {
        // 这个方法不直接执行编译，而是由 Compiler 类调用
        // 这里只返回成功，实际编译在 Compiler::compile() 中完成
        RunCompilerResult res;
        res.succeeded = true;
        res.ust = 0;
        res.usm = 0;
        return res;
    }
    
    // 获取 setup 配置
    yaml::YamlNodePtr get_setup_config() const {
        return config_->get("setup");
    }
    
    // 执行 setup 步骤
    bool execute_setup(const std::string& work_dir) const {
        auto setup = get_setup_config();
        if (!setup || !setup->is_list()) return true;
        
        for (const auto& step : setup->as_list()) {
            if (step->has("write_file")) {
                auto write_file = step->get("write_file");
                std::string path = work_dir + "/" + write_file->get("path")->as_string();
                std::string content = write_file->get("content")->as_string();
                
                FILE* f = fopen(path.c_str(), "w");
                if (!f) return false;
                fprintf(f, "%s\n", content.c_str());
                fclose(f);
            }
        }
        return true;
    }
};

/**
 * @brief 从目录加载所有语言配置
 */
inline void load_languages_from_directory(const std::string& dir) {
    namespace fs = std::filesystem;
    
    if (!fs::exists(dir)) {
        return;
    }
    
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.path().extension() == ".yaml" || entry.path().extension() == ".yml") {
            try {
                auto config = yaml::load_yaml(entry.path().string());
                auto plugin = std::make_shared<YamlLanguagePlugin>(config);
                LanguageRegistry::instance().register_plugin(plugin);
            } catch (const std::exception& e) {
                std::cerr << "Error loading " << entry.path() << ": " << e.what() << std::endl;
            }
        }
    }
}

} // namespace uoj

#endif // UOJ_CORE_LANGUAGE_LOADER_H
