/**
 * @file main_judger.cpp
 * @brief 主评测入口
 * 
 * 根据 problem.conf 中的 use_builtin_judger 配置：
 * - on:  调用 builtin/judger/judger
 * - off: 调用 data/{problem_id}/judger（自定义 judger）
 * 
 * 自定义 judger 使用 problem.yml 用户权限配置运行
 */

#include "uoj_judger_new.h"
#include "sandbox/cgroup.h"

using namespace uoj;

int main(int argc, char **argv) {
    // 初始化 cgroup 管理器
    // 这会：
    // 1. 检测当前进程的 cgroup 路径（可能是 systemd-run 创建的 scope）
    // 2. 创建 judger/ 和 sandbox/ 子 cgroup
    // 3. 将当前进程移动到 judger/（遵循 cgroup v2 "no internal processes" 规则）
    auto cgroup_result = sandbox::CgroupManager::instance().initialize();
    if (!cgroup_result.ok()) {
        std::cerr << "Warning: Failed to initialize cgroup: " 
                  << cgroup_result.error().message() << std::endl;
        // 继续执行，可能在无 cgroup 支持的环境中
    }
    
    JudgeContext ctx;
    ctx.init_main_judger();
    
    // 获取 judger 路径
    std::string judger_path = ctx.config.get_str("judger");
    RunLimit limit = ctx.config.get_run_limit("judger", 0, limits::JUDGER);
    
    // 加载 problem 用户配置（用于限制自定义 judger）
    Sys sys = Sys::get("problem");
    
    // 执行 judger
    ExecResult result = sys
        .work_dir(ctx.work_path)
        .limit(limit)
        .add_readonly(ctx.main_path)
        .add_readonly(ctx.data_path)
        .add_readonly("/usr")
        .add_readonly("/lib")
        .add_readonly("/lib64")
        .add_readonly("/bin")
        .add_readonly("/etc")
        .add_writable(ctx.work_path)
        .add_writable(ctx.result_path)
        .exec(judger_path, {
            ctx.main_path,
            ctx.work_path,
            ctx.result_path,
            ctx.data_path
        });
    
    if (!result.ok) {
        JudgeResult::write_judgement_failed(ctx.result_path, 
            "Judgement Failed: " + result.error);
        return 1;
    }
    
    if (result.status != sandbox::RunStatus::OK) {
        JudgeResult::write_judgement_failed(ctx.result_path,
            "Judgement Failed: Judger " + 
            std::string(sandbox::status_to_string(result.status)));
        return 1;
    }
    
    return 0;
}

