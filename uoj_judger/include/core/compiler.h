/**
 * @file compiler.h
 * @brief 编译器 - 使用现代沙箱 (seccomp-bpf + cgroups v2)
 */

#ifndef UOJ_CORE_COMPILER_H
#define UOJ_CORE_COMPILER_H

#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include "core/types.h"
#include "core/utils.h"
#include "core/config.h"
#include "core/language.h"
#include "core/system.h"  // 统一的系统命令执行入口

namespace uoj {

/**
 * @brief 编译器 - 使用现代沙箱
 */
class Compiler {
private:
    std::string main_path_;
    std::string work_path_;
    std::string result_path_;
    std::string data_path_;
    Config* config_;

public:
    Compiler(const std::string &main_path, const std::string &work_path,
             const std::string &result_path, const std::string &data_path,
             Config* config)
        : main_path_(main_path), work_path_(work_path),
          result_path_(result_path), data_path_(data_path), config_(config) {}

    /**
     * @brief 编译源代码
     */
    RunCompilerResult compile(const std::string &name) {
        // 优先使用 "answer_language"，回退到 "language"
        std::string lang = config_->get_str(name + "_language");
        if (lang.empty()) {
            lang = config_->get_str("language");
        }
        
        auto* plugin = LanguageRegistry::instance().get(lang);
        if (!plugin) {
            RunCompilerResult res = RunCompilerResult::failed_result();
            res.info = "Language not supported: " + lang;
            return res;
        }
        
        // 检查非法关键字
        if (plugin->check_illegal_keywords()) {
            std::string source_file = work_path_ + "/" + name + ".code";
            if (has_illegal_keywords_in_file(source_file)) {
                RunCompilerResult res;
                res.type = RS_DGS;
                res.ust = -1;
                res.usm = -1;
                res.succeeded = false;
                res.info = "Compile Failed";
                return res;
            }
        }
        
        // 如果不需要编译
        if (!plugin->needs_compile()) {
            RunCompilerResult res;
            res.type = RS_AC;
            res.ust = 0;
            res.usm = 0;
            res.succeeded = true;
            return res;
        }
        
        // 获取编译命令和参数（使用基类接口）
        std::string compiler_cmd = plugin->get_compiler_command();
        std::vector<std::string> args = plugin->get_compiler_args();
        RunLimit limit = plugin->get_compiler_limit();
        
        // 替换占位符
        std::string source = name + ".code";
        std::string output = name;
        std::string main_class = "Main";  // Java 默认主类名
        
        // Java 需要把源文件复制为 Main.java
        if (compiler_cmd.find("javac") != std::string::npos) {
            std::string java_source = work_path_ + "/" + main_class + ".java";
            std::string code_source = work_path_ + "/" + source;
            
            // 复制文件
            std::ifstream src(code_source, std::ios::binary);
            std::ofstream dst(java_source, std::ios::binary);
            if (src && dst) {
                dst << src.rdbuf();
            }
        }
        
        for (auto& arg : args) {
            size_t pos;
            while ((pos = arg.find("{source}")) != std::string::npos) {
                arg.replace(pos, 8, source);
            }
            while ((pos = arg.find("{output}")) != std::string::npos) {
                arg.replace(pos, 8, output);
            }
            while ((pos = arg.find("{work_path}")) != std::string::npos) {
                arg.replace(pos, 11, work_path_);
            }
            while ((pos = arg.find("{main_class}")) != std::string::npos) {
                arg.replace(pos, 12, main_class);
            }
        }
        
        // 选择 Sys 配置（由语言插件决定）
        std::string sandbox_type = plugin ? plugin->compiler_sandbox_type() : "compiler";
        Sys sys = Sys::get(sandbox_type);
        
        ExecResult exec_res = sys
            .work_dir(work_path_)
            .limit(limit)
            .stderr_file(result_path_ + "/compiler_result.txt")
            .exec(compiler_cmd, args);
        
        // 转换结果
        RunCompilerResult res;
        res.ust = exec_res.time_ms;
        res.usm = exec_res.memory_kb;
        res.type = (exec_res.status == sandbox::RunStatus::OK && exec_res.exit_code == 0) 
                   ? RS_AC : RS_RE;
        res.succeeded = (exec_res.status == sandbox::RunStatus::OK && exec_res.exit_code == 0);
        
        if (!res.succeeded) {
            // 编译器退出码非零是正常的（表示编译失败）
            if (exec_res.status == sandbox::RunStatus::OK || 
                exec_res.status == sandbox::RunStatus::RUNTIME_ERROR) {
                res.info = file_preview(result_path_ + "/compiler_result.txt", 500);
                if (res.info.empty()) {
                    res.info = "Compile failed with exit code " + std::to_string(exec_res.exit_code);
                }
            } else if (exec_res.status == sandbox::RunStatus::SECCOMP_VIOLATION) {
                res.type = RS_DGS;
                res.info = "Compiler Dangerous Syscalls";
            } else if (exec_res.status == sandbox::RunStatus::TIME_LIMIT) {
                res.type = RS_TLE;
                res.info = "Compiler Time Limit Exceeded";
            } else if (exec_res.status == sandbox::RunStatus::MEMORY_LIMIT) {
                res.type = RS_MLE;
                res.info = "Compiler Memory Limit Exceeded";
            } else {
                res.info = "Compiler " + std::string(sandbox::status_to_string(exec_res.status));
            }
        } else {
            // 对于需要 main_class 的语言（如 Java），设置默认值
            if (plugin && plugin->needs_main_class()) {
                config_->set(name + "_main_class", plugin->get_default_main_class());
            }
        }
        
        return res;
    }
    
    /**
     * @brief 带 implementer 编译（用于交互式题目）
     * 
     * implementer 是一个框架程序，用户代码会和它一起编译。
     * 主要用于函数式交互题，用户只需实现特定函数。
     */
    RunCompilerResult compile_with_implementer(const std::string &name) {
        std::string lang = config_->get_str(name + "_language");
        
        RunCompilerResult res;
        res.succeeded = false;
        res.info = "";
        
        // 检查 implementer 文件是否存在
        std::string impl_cpp = work_path_ + "/implementer.cpp";
        std::string impl_c = work_path_ + "/implementer.c";
        std::string impl_pas = work_path_ + "/implementer.pas";
        std::string source = work_path_ + "/" + name + ".code";
        std::string output = work_path_ + "/" + name;
        
        // 构建编译命令
        std::string compiler_cmd;
        std::vector<std::string> compiler_args;
        
        // 根据语言构建编译命令
        if (lang == "C++" || lang == "C++11" || lang == "C++14" || lang == "C++17" || lang == "C++20") {
            compiler_cmd = "/usr/bin/g++";
            compiler_args = {"-o", output};
            
            if (file_exists(impl_cpp)) {
                compiler_args.push_back(impl_cpp);
            }
            compiler_args.push_back("-x");
            compiler_args.push_back("c++");
            compiler_args.push_back(source);
            compiler_args.push_back("-lm");
            compiler_args.push_back("-O2");
            compiler_args.push_back("-DONLINE_JUDGE");
            
            if (lang == "C++11") {
                compiler_args.push_back("-std=c++11");
            } else if (lang == "C++14") {
                compiler_args.push_back("-std=c++14");
            } else if (lang == "C++17") {
                compiler_args.push_back("-std=c++17");
            } else if (lang == "C++20") {
                compiler_args.push_back("-std=c++20");
            }
        } else if (lang == "C") {
            compiler_cmd = "/usr/bin/gcc";
            compiler_args = {"-o", output};
            if (file_exists(impl_c)) {
                compiler_args.push_back(impl_c);
            }
            compiler_args.push_back("-x");
            compiler_args.push_back("c");
            compiler_args.push_back(source);
            compiler_args.push_back("-lm");
            compiler_args.push_back("-O2");
            compiler_args.push_back("-DONLINE_JUDGE");
        } else if (lang == "Pascal") {
            // Pascal: fpc implementer.pas -o<name>
            if (file_exists(impl_pas)) {
                compiler_cmd = "/usr/bin/fpc";
                compiler_args = {impl_pas, "-o" + output, "-O2"};
            } else {
                return compile(name);  // 无 implementer，普通编译
            }
        } else {
            // 其他语言不支持 implementer，普通编译
            return compile(name);
        }
        
        auto* plugin = LanguageRegistry::instance().get(lang);
        RunLimit limit = plugin ? plugin->get_compiler_limit() : limits::DEFAULT;
        
        // 通过 Sys 执行编译
        ExecResult exec_res = Sys::get("compiler")
            .work_dir(work_path_)
            .limit(limit)
            .stderr_file(result_path_ + "/compiler_result.txt")
            .exec(compiler_cmd, compiler_args);
        
        if (exec_res.status == sandbox::RunStatus::OK && exec_res.exit_code == 0) {
            res.succeeded = true;
            res.info = "Compile success";
        } else {
            res.succeeded = false;
            res.info = file_preview(result_path_ + "/compiler_result.txt", 4096);
            if (res.info.empty()) {
                res.info = exec_res.error;
            }
        }
        
        return res;
    }
    
private:
    bool file_exists(const std::string &path) {
        return access(path.c_str(), F_OK) == 0;
    }
};

} // namespace uoj

#endif // UOJ_CORE_COMPILER_H
