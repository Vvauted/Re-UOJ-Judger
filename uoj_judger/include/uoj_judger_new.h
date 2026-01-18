/**
 * @file uoj_judger_new.h
 * @brief UOJ 评测机新版主头文件
 * 
 * 使用现代沙箱 (seccomp-bpf + cgroups v2)
 * 
 * 使用方式：
 *   #include "uoj_judger_new.h"
 *   using namespace uoj;
 */

#ifndef UOJ_JUDGER_NEW_H
#define UOJ_JUDGER_NEW_H

// 标准库
#include <memory>
#include <unistd.h>
#include <linux/limits.h>

// 核心模块
#include "uoj_env.h"
#include "core/types.h"
#include "core/utils.h"
#include "core/config.h"
#include "core/result.h"
#include "core/language.h"
#include "core/language_loader.h"
#include "core/runner.h"
#include "core/compiler.h"
#include "core/logger.h"
#include "core/judger_logger.h"

// 沙箱
#include "sandbox/sandbox.h"

namespace uoj {

/**
 * @brief 初始化语言插件
 * 
 * 从 YAML 配置目录加载所有语言插件
 * @param config_dir 语言配置目录，默认 "/opt/uoj_judger/config/languages"
 */
inline void init_languages(const std::string& config_dir = "/opt/uoj_judger/config/languages") {
    load_languages_from_directory(config_dir);
}

/**
 * @brief 评测上下文
 * 
 * 封装评测所需的所有状态和组件
 */
class JudgeContext {
public:
    // 路径
    std::string main_path;
    std::string work_path;
    std::string result_path;
    std::string data_path;
    
    // 题目信息
    int problem_id = 0;
    
    // 配置
    Config config;
    
    // 结果收集器
    JudgeResult result;
    
    // 组件
    std::unique_ptr<Runner> runner;
    std::unique_ptr<Compiler> compiler;

public:
    JudgeContext() = default;
    
    /**
     * @brief 初始化评测上下文（用于 main_judger）
     */
    void init_main_judger() {
        main_path = UOJ_WORK_PATH;
        work_path = main_path + "/work";
        result_path = std::string(UOJ_RESULT_PATH);
        
        // 初始化语言插件
        init_languages(main_path + "/config/languages");
        
        config.load(work_path + "/submission.conf");
        problem_id = config.get_int("problem_id");
        data_path = std::string(UOJ_DATA_PATH) + "/" + config.get_str("problem_id");
        config.load(data_path + "/problem.conf");

        // 复制题目依赖文件
        executef("cp %s/require/* %s 2>/dev/null", data_path.c_str(), work_path.c_str());

        // 设置评测器路径
        if (config.is("use_builtin_judger", "on")) {
            config.set("judger", std::string(UOJ_WORK_PATH) + "/builtin/judger/judger");
        } else {
            config.set("judger", data_path + "/judger");
        }
        
        init_components();
    }
    
    /**
     * @brief 初始化评测上下文（用于 judger）
     * 兼容两种调用方式：
     * 1. 无参数：使用默认路径（兼容原 UOJ judge_client）
     * 2. 4个参数：main_path work_path result_path data_path
     */
    void init_judger(int argc, char **argv) {
        // 获取可执行文件的实际路径（比 getcwd 更可靠）
        char exe_path[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len == -1) {
            perror("readlink /proc/self/exe");
            exit(1);
        }
        exe_path[len] = '\0';
        
        // 从可执行文件路径获取目录
        std::string exe_dir = exe_path;
        size_t last_slash = exe_dir.rfind('/');
        if (last_slash != std::string::npos) {
            exe_dir = exe_dir.substr(0, last_slash);
        }
        
        // 获取当前工作目录用于转换相对路径
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) == nullptr) {
            exit(1);
        }
        std::string current_dir = cwd;
        
        // 辅助函数：确保路径是绝对路径
        auto make_absolute = [&current_dir](const std::string& path) -> std::string {
            if (path.empty() || path[0] == '/') {
                return path;  // 已经是绝对路径
            }
            return current_dir + "/" + path;
        };
        
        if (argc == 5) {
            // 新调用方式：显式传递路径
            main_path = make_absolute(argv[1]);
            work_path = make_absolute(argv[2]);
            result_path = make_absolute(argv[3]);
            data_path = make_absolute(argv[4]);
        } else {
            // 兼容模式：使用可执行文件所在目录作为 main_path
            // 这样无论从哪里调用 main_judger 都能正常工作
            main_path = exe_dir;
            work_path = exe_dir + "/work";
            result_path = exe_dir + "/result";
            // data_path 需要从 submission.conf 读取 problem_id 后设置
        }
        
        // 初始化语言插件
        init_languages(main_path + "/config/languages");
        
        config.load(work_path + "/submission.conf");
        problem_id = config.get_int("problem_id");
        
        // 初始化 Sys 系统（加载用户配置）
        Sys::init(main_path + "/config");
        
        // 兼容模式下设置 data_path
        if (data_path.empty()) {
            data_path = main_path + "/data/" + std::to_string(problem_id);
        }
        
        config.load(data_path + "/problem.conf");

        // 设置 checker 路径
        if (config.has("use_builtin_checker")) {
            config.set("checker", main_path + "/builtin/checker/" + config.get_str("use_builtin_checker"));
        } else {
            config.set("checker", data_path + "/chk");
        }
        config.set("validator", data_path + "/val");
        
        init_components();
    }
    
    /**
     * @brief 报告评测状态
     */
    void report_status(const char *status) {
        uoj::report_status(result_path, status);
    }
    
    template<typename... Args>
    void report_status_f(const char *fmt, Args... args) {
        uoj::report_status_f(result_path, fmt, args...);
    }
    
    /**
     * @brief 结束评测 - 成功
     */
    [[noreturn]] void end_ok() {
        result.write_ok(result_path);
        exit(0);
    }
    
    /**
     * @brief 结束评测 - 评测失败
     */
    [[noreturn]] void end_judgement_failed(const std::string &info) {
        JudgeResult::write_judgement_failed(result_path, info);
        exit(1);
    }
    
    /**
     * @brief 结束评测 - 编译错误
     */
    [[noreturn]] void end_compile_error(const RunCompilerResult &res) {
        JudgeResult::write_compile_error(result_path, res);
        exit(0);
    }

private:
    void init_components() {
        runner = std::make_unique<Runner>(main_path, work_path, result_path, data_path, &config);
        compiler = std::make_unique<Compiler>(main_path, work_path, result_path, data_path, &config);
        
        // 输出沙箱状态
        sandbox::check_sandbox_features();
    }
};

/**
 * @brief 测试点配置
 */
struct TestPointConfig {
    int submit_answer = -1;
    int validate_input_before_test = -1;
    std::string input_file_name;
    std::string output_file_name;
    std::string answer_file_name;

    void auto_complete(int num, const JudgeContext &ctx) {
        if (submit_answer == -1) {
            submit_answer = ctx.config.is("submit_answer", "on");
        }
        if (validate_input_before_test == -1) {
            validate_input_before_test = ctx.config.is("validate_input_before_test", "on");
        }
        if (input_file_name.empty()) {
            input_file_name = ctx.data_path + "/" + ctx.config.get_input_filename(num);
        }
        if (output_file_name.empty()) {
            output_file_name = ctx.work_path + "/" + ctx.config.get_output_filename(num);
        }
        if (answer_file_name.empty()) {
            answer_file_name = ctx.data_path + "/" + ctx.config.get_output_filename(num);
        }
    }
};

/**
 * @brief 测试单个测试点
 */
inline PointInfo test_point(JudgeContext &ctx, const std::string &name, int num, 
                            TestPointConfig tpc = TestPointConfig()) {
    tpc.auto_complete(num, ctx);

    // 输入验证（可选）
    if (tpc.validate_input_before_test) {
        RunValidatorResult val_ret = ctx.runner->run_validator(
            tpc.input_file_name,
            ctx.config.get_run_limit("validator", 0, limits::VALIDATOR),
            ctx.config.get_str("validator"));
        
        if (val_ret.type != RS_AC) {
            return PointInfo(num, 0, -1, -1,
                "Validator " + result_to_string(val_ret.type),
                file_preview(tpc.input_file_name), "", "");
        } else if (!val_ret.succeeded) {
            return PointInfo(num, 0, -1, -1, "Invalid Input",
                file_preview(tpc.input_file_name), "", val_ret.info);
        }
    }

    // 非交互模式
    if (!ctx.config.is("interaction_mode", "on")) {
        RunResult pro_ret;
        if (!tpc.submit_answer) {
            pro_ret = ctx.runner->run_submission(
                tpc.input_file_name,
                tpc.output_file_name,
                ctx.config.get_run_limit(num, limits::DEFAULT),
                name);
            
            if (ctx.config.has("token")) {
                file_hide_token(tpc.output_file_name, ctx.config.get_str("token", ""));
            }
            if (pro_ret.type != RS_AC) {
                return PointInfo(num, 0, -1, -1,
                    result_to_string(pro_ret.type),
                    file_preview(tpc.input_file_name), file_preview(tpc.output_file_name), "");
            }
        } else {
            pro_ret.type = RS_AC;
            pro_ret.ust = -1;
            pro_ret.usm = -1;
            pro_ret.exit_code = 0;
        }

        RunCheckerResult chk_ret = ctx.runner->run_checker(
            ctx.config.get_run_limit("checker", num, limits::CHECKER),
            ctx.config.get_str("checker"),
            tpc.input_file_name,
            tpc.output_file_name,
            tpc.answer_file_name);
        
        if (chk_ret.type != RS_AC) {
            return PointInfo(num, 0, -1, -1,
                "Checker " + result_to_string(chk_ret.type),
                file_preview(tpc.input_file_name), file_preview(tpc.output_file_name), "");
        }

        return PointInfo(num, chk_ret.scr, pro_ret.ust, pro_ret.usm, "default",
            file_preview(tpc.input_file_name), file_preview(tpc.output_file_name), chk_ret.info);
    }
    
    // 交互模式
    std::string real_output_file_name = tpc.output_file_name + ".real_input.txt";
    std::string real_input_file_name = tpc.output_file_name + ".real_output.txt";
    
    RunSimpleInteractionResult rires = ctx.runner->run_simple_interaction(
        tpc.input_file_name,
        tpc.answer_file_name,
        real_input_file_name,
        real_output_file_name,
        ctx.config.get_run_limit(num, limits::DEFAULT),
        ctx.config.get_run_limit("interactor", num, limits::INTERACTOR),
        name);
    
    if (rires.ires.type != RS_AC) {
        return PointInfo(num, 0, -1, -1,
            "Interactor " + result_to_string(rires.ires.type),
            file_preview(real_input_file_name), file_preview(real_output_file_name), "");
    }
    if (rires.res.type != RS_AC) {
        return PointInfo(num, 0, -1, -1,
            result_to_string(rires.res.type),
            file_preview(real_input_file_name), file_preview(real_output_file_name), "");
    }
    
    return PointInfo(num, rires.ires.scr, rires.res.ust, rires.res.usm, "default",
        file_preview(real_input_file_name), file_preview(real_output_file_name), rires.ires.info);
}

/**
 * @brief 普通自定义测试
 */
inline CustomTestInfo ordinary_custom_test(JudgeContext &ctx, const std::string &name) {
    RunLimit lim = ctx.config.get_run_limit(0, limits::DEFAULT);
    lim.time += 2;

    std::string input_file_name = ctx.work_path + "/input.txt";
    std::string output_file_name = ctx.work_path + "/output.txt";

    RunResult pro_ret = ctx.runner->run_submission(
        input_file_name, output_file_name, lim, name);
    
    if (ctx.config.has("token")) {
        file_hide_token(output_file_name, ctx.config.get_str("token", ""));
    }
    
    std::string info = (pro_ret.type == RS_AC) ? "Success" : result_to_string(pro_ret.type);
    std::string exp;
    if (pro_ret.type == RS_TLE) {
        exp = "<p>[<strong>time limit:</strong> " + to_string(lim.time) + "s]</p>";
    }
    return CustomTestInfo(pro_ret.ust, pro_ret.usm, info, exp, file_preview(output_file_name, 2048));
}

/**
 * @brief 分数缩放
 */
inline int scale_score(int scr100, int full) {
    return scr100 * full / 100;
}

/**
 * @brief Hack 测试点
 * 
 * 验证 hack 输入是否有效，并测试用户程序
 * @param ctx JudgeContext
 * @param name 程序名称
 * @param tpc 测试点配置
 * @return PointInfo 测试结果，scr=1表示hack成功，scr=0表示hack失败
 */
inline PointInfo test_hack_point(JudgeContext &ctx, const std::string &name, 
                                  TestPointConfig tpc = TestPointConfig()) {
    tpc.submit_answer = false;
    tpc.validate_input_before_test = false;
    tpc.auto_complete(0, ctx);
    
    // 1. 验证 hack 输入是否有效
    RunValidatorResult val_ret = ctx.runner->run_validator(
        tpc.input_file_name,
        ctx.config.get_run_limit("validator", 0, limits::VALIDATOR),
        ctx.config.get_str("validator"));
    
    if (val_ret.type != RS_AC) {
        return PointInfo(0, 0, -1, -1,
            "Validator " + result_to_string(val_ret.type),
            file_preview(tpc.input_file_name), "", "");
    } else if (!val_ret.succeeded) {
        return PointInfo(0, 0, -1, -1,
            "Invalid Input",
            file_preview(tpc.input_file_name), "", val_ret.info);
    }
    
    RunLimit default_std_run_limit = ctx.config.get_run_limit(0, limits::DEFAULT);
    
    // 2. 运行标准程序生成正确答案
    if (!ctx.config.is("interaction_mode", "on")) {
        // 非交互模式：运行标程生成答案
        RunResult std_ret = ctx.runner->run_submission(
            tpc.input_file_name,
            tpc.answer_file_name,
            ctx.config.get_run_limit("standard", 0, default_std_run_limit),
            "std");
        
        if (std_ret.type != RS_AC) {
            return PointInfo(0, 0, -1, -1,
                "Standard Program " + result_to_string(std_ret.type),
                file_preview(tpc.input_file_name), "", "");
        }
        
        if (ctx.config.has("token")) {
            file_hide_token(tpc.answer_file_name, ctx.config.get_str("token", ""));
        }
    } else {
        // 交互模式：使用标程作为交互对象生成答案
        std::string real_output_file_name = tpc.answer_file_name;
        std::string real_input_file_name = tpc.output_file_name + ".real_output.txt";
        
        RunSimpleInteractionResult rires = ctx.runner->run_simple_interaction(
            tpc.input_file_name,
            tpc.answer_file_name,
            real_input_file_name,
            real_output_file_name,
            ctx.config.get_run_limit("standard", 0, default_std_run_limit),
            ctx.config.get_run_limit("interactor", 0, limits::INTERACTOR),
            "std");
        
        if (rires.ires.type != RS_AC) {
            return PointInfo(0, 0, -1, -1,
                "Interactor " + result_to_string(rires.ires.type) + " (Standard Program)",
                file_preview(real_input_file_name), "", "");
        }
        if (rires.res.type != RS_AC) {
            return PointInfo(0, 0, -1, -1,
                "Standard Program " + result_to_string(rires.res.type),
                file_preview(real_input_file_name), "", "");
        }
    }
    
    // 3. 运行用户程序并评测
    PointInfo po = test_point(ctx, name, 0, tpc);
    
    // 4. 判断 hack 是否成功：用户程序得分 < 100 表示 hack 成功
    po.scr = (po.scr != 100) ? 1 : 0;
    return po;
}

} // namespace uoj

#endif // UOJ_JUDGER_NEW_H
