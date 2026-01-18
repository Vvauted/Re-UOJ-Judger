/**
 * @file judger_new.cpp
 * @brief 使用新 API 的评测器示例
 * 
 * 展示如何使用重构后的评测机 API
 */

#include "uoj_judger_new.h"
#include <map>

using namespace uoj;

// 全局评测上下文
JudgeContext ctx;

struct SubtaskInfo {
    bool passed;
    int score;
    SubtaskInfo() : passed(false), score(0) {}
    SubtaskInfo(bool p, int s) : passed(p), score(s) {}
};

/**
 * @brief 普通评测
 */
void ordinary_test() {
    int n = ctx.config.get_int("n_tests", 10);
    int m = ctx.config.get_int("n_ex_tests", 0);
    int nT = ctx.config.get_int("n_subtasks", 0);

    // 编译
    if (!ctx.config.is("submit_answer", "on")) {
        ctx.report_status("Compiling");
        RunCompilerResult c_ret = ctx.config.is("with_implementer", "on") 
            ? ctx.compiler->compile_with_implementer("answer")
            : ctx.compiler->compile("answer");
        
        if (!c_ret.succeeded) {
            ctx.end_compile_error(c_ret);
        }
    }

    bool passed = true;
    
    if (nT == 0) {
        // 无子任务：简单评测每个点
        for (int i = 1; i <= n; i++) {
            ctx.report_status_f("Judging Test #%d", i);
            PointInfo po = test_point(ctx, "answer", i);
            if (po.scr != 100) {
                passed = false;
            }
            po.scr = scale_score(po.scr, ctx.config.get_int("point_score", i, 100 / n));
            ctx.result.add_point(po, ctx.config);
        }
    } else if (nT == 1 && ctx.config.get_str("subtask_type", 1, "packed") == "packed") {
        // 单个打包子任务
        int tfull = ctx.config.get_int("subtask_score", 1, 100);
        for (int i = 1; i <= n; i++) {
            ctx.report_status_f("Judging Test #%d", i);
            PointInfo po = test_point(ctx, "answer", i);
            if (po.scr != 100) {
                passed = false;
                po.scr = (i == 1) ? 0 : -tfull;
                ctx.result.add_point(po, ctx.config);
                break;
            } else {
                po.scr = (i == 1) ? tfull : 0;
                ctx.result.add_point(po, ctx.config);
            }
        }
    } else {
        // 多子任务
        std::map<int, SubtaskInfo> subtasks;
        std::map<int, int> minScore;
        
        for (int t = 1; t <= nT; t++) {
            std::string subtaskType = ctx.config.get_str("subtask_type", t, "packed");
            int startI = ctx.config.get_int("subtask_end", t - 1, 0) + 1;
            int endI = ctx.config.get_int("subtask_end", t, 0);

            std::vector<PointInfo> points;
            minScore[t] = 100;

            // 处理依赖
            std::vector<int> dependences;
            if (ctx.config.get_str("subtask_dependence", t, "none") == "many") {
                std::string cur = "subtask_dependence_" + to_string(t);
                int p = 1;
                while (ctx.config.get_int(cur, p, 0) != 0) {
                    dependences.push_back(ctx.config.get_int(cur, p, 0));
                    p++;
                }
            } else if (ctx.config.get_int("subtask_dependence", t, 0) != 0) {
                dependences.push_back(ctx.config.get_int("subtask_dependence", t, 0));
            }
            
            bool skipped = false;
            for (int dep : dependences) {
                if (subtaskType == "packed") {
                    if (!subtasks[dep].passed) {
                        skipped = true;
                        break;
                    }
                } else if (subtaskType == "min") {
                    minScore[t] = std::min(minScore[t], minScore[dep]);
                }
            }
            
            if (skipped) {
                ctx.result.add_subtask(t, 0, "Skipped", points, ctx.config);
                continue;
            }

            int tfull = ctx.config.get_int("subtask_score", t, 100 / nT);
            int tscore = scale_score(minScore[t], tfull);
            std::string info = "Accepted";
            
            for (int i = startI; i <= endI; i++) {
                ctx.report_status_f("Judging Test #%d of Subtask #%d", i, t);
                PointInfo po = test_point(ctx, "answer", i);
                
                if (subtaskType == "packed") {
                    if (po.scr != 100) {
                        passed = false;
                        po.scr = (i == startI) ? 0 : -tfull;
                        tscore = 0;
                        points.push_back(po);
                        info = po.info;
                        break;
                    } else {
                        po.scr = (i == startI) ? tfull : 0;
                        tscore = tfull;
                        points.push_back(po);
                    }
                } else if (subtaskType == "min") {
                    minScore[t] = std::min(minScore[t], po.scr);
                    if (po.scr != 100) {
                        passed = false;
                    }
                    po.scr = scale_score(po.scr, tfull);
                    if (po.scr <= tscore) {
                        tscore = po.scr;
                        points.push_back(po);
                        info = po.info;
                    } else {
                        points.push_back(po);
                    }
                }
            }

            subtasks[t] = SubtaskInfo(info == "Accepted", tscore);
            ctx.result.add_subtask(t, tscore, info, points, ctx.config);
        }
    }
    
    if (ctx.config.is("submit_answer", "on") || !passed) {
        ctx.end_ok();
    }

    // 额外测试
    ctx.result.set_total_score(100);
    for (int i = 1; i <= m; i++) {
        ctx.report_status_f("Judging Extra Test #%d", i);
        PointInfo po = test_point(ctx, "answer", -i);
        if (po.scr != 100) {
            po.num = -1;
            po.info = "Extra Test Failed : " + po.info + " on " + to_string(i);
            po.scr = -3;
            ctx.result.add_point(po, ctx.config);
            ctx.end_ok();
        }
    }
    if (m != 0) {
        PointInfo po(-1, 0, -1, -1, "Extra Test Passed", "", "", "");
        ctx.result.add_point(po, ctx.config);
    }
    ctx.end_ok();
}

/**
 * @brief Hack 测试
 * 
 * 流程：
 * 1. 编译用户程序和标程
 * 2. 验证 hack 输入是否合法
 * 3. 运行标程生成正确答案
 * 4. 运行用户程序并比较结果
 * 5. 如果用户程序出错或答案错误，hack 成功
 */
void hack_test() {
    if (ctx.config.is("submit_answer", "on")) {
        ctx.end_judgement_failed("Hack is not supported in this problem.");
    }
    
    // 编译用户程序
    RunCompilerResult c_ret = ctx.config.is("with_implementer", "on")
        ? ctx.compiler->compile_with_implementer("answer")
        : ctx.compiler->compile("answer");
    
    if (!c_ret.succeeded) {
        ctx.end_compile_error(c_ret);
    }
    
    // 编译标准程序
    ctx.report_status("Compiling Standard Program");
    RunCompilerResult std_ret = ctx.compiler->compile("std");
    if (!std_ret.succeeded) {
        ctx.end_judgement_failed("Standard program compile error");
    }
    
    // 配置测试点
    TestPointConfig tpc;
    tpc.input_file_name = ctx.work_path + "/hack_input.txt";
    tpc.output_file_name = ctx.work_path + "/output.txt";
    tpc.answer_file_name = ctx.work_path + "/answer.txt";
    
    // 执行 hack 测试
    ctx.report_status("Running Hack Test");
    PointInfo po = test_hack_point(ctx, "answer", tpc);
    
    // 报告结果
    ctx.result.add_point(po, ctx.config);
    
    if (po.scr == 1) {
        // Hack 成功
        ctx.end_ok();
    } else if (po.res == "Invalid Input") {
        // Hack 输入无效
        ctx.end_judgement_failed("Invalid hack input: " + po.info);
    } else {
        // Hack 失败（用户程序正确）
        ctx.end_ok();
    }
}

/**
 * @brief 样例测试
 */
void sample_test() {
    if (ctx.config.is("submit_answer", "on")) {
        int n = ctx.config.get_int("n_tests", 10);
        for (int i = 1; i <= n; i++) {
            ctx.report_status_f("Judging Test #%d", i);
            
            if (ctx.config.is("check_existence_only_in_sample_test", "on")) {
                TestPointConfig tpc;
                tpc.auto_complete(i, ctx);
                
                std::string usrout = file_preview(tpc.output_file_name);
                if (usrout.empty()) {
                    PointInfo po(i, 0, -1, -1, "default",
                        file_preview(tpc.input_file_name), usrout,
                        "wrong answer empty file\n");
                    ctx.result.add_point(po, ctx.config);
                } else {
                    PointInfo po(i, 100, -1, -1, "default",
                        file_preview(tpc.input_file_name), usrout,
                        "ok nonempty file\n");
                    po.scr = scale_score(po.scr, ctx.config.get_int("point_score", i, 100 / n));
                    ctx.result.add_point(po, ctx.config);
                }
            } else {
                PointInfo po = test_point(ctx, "answer", i);
                if (po.scr != 0) {
                    po.info = "Accepted";
                    po.scr = 100;
                }
                po.scr = scale_score(po.scr, ctx.config.get_int("point_score", i, 100 / n));
                po.res = "no comment";
                ctx.result.add_point(po, ctx.config);
            }
        }
        ctx.end_ok();
    }
    
    ctx.report_status("Compiling");
    RunCompilerResult c_ret = ctx.config.is("with_implementer", "on")
        ? ctx.compiler->compile_with_implementer("answer")
        : ctx.compiler->compile("answer");
    
    if (!c_ret.succeeded) {
        ctx.end_compile_error(c_ret);
    }

    int n = ctx.config.get_int("n_sample_tests", 0);
    bool passed = true;
    for (int i = 1; i <= n; i++) {
        ctx.report_status_f("Judging Sample Test #%d", i);
        PointInfo po = test_point(ctx, "answer", -i);
        po.num = i;
        if (po.scr != 100) {
            passed = false;
        }
        po.scr = scale_score(po.scr, 100 / n);
        ctx.result.add_point(po, ctx.config);
    }
    if (passed) {
        ctx.result.set_total_score(100);
    }
    ctx.end_ok();
}

/**
 * @brief 自定义测试
 */
void custom_test() {
    if (ctx.config.is("submit_answer", "on")) {
        ctx.end_judgement_failed("Custom test is not supported in this problem.");
    }
    
    ctx.report_status("Compiling");
    RunCompilerResult c_ret = ctx.config.is("with_implementer", "on")
        ? ctx.compiler->compile_with_implementer("answer")
        : ctx.compiler->compile("answer");
    
    if (!c_ret.succeeded) {
        ctx.end_compile_error(c_ret);
    }
    
    ctx.report_status("Judging");
    ctx.result.add_custom_test(ordinary_custom_test(ctx, "answer"));
    
    ctx.end_ok();
}

int main(int argc, char **argv) {
    ctx.init_judger(argc, argv);

    if (ctx.config.is("test_new_hack_only", "on")) {
        hack_test();
    } else if (ctx.config.is("test_sample_only", "on")) {
        sample_test();
    } else if (ctx.config.is("custom_test", "on")) {
        custom_test();
    } else {
        ordinary_test();
    }
    
    return 0;
}

