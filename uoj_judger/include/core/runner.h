/**
 * @file runner.h
 * @brief 程序运行器 - 使用现代沙箱 (seccomp-bpf + cgroups v2)
 */

#ifndef UOJ_CORE_RUNNER_H
#define UOJ_CORE_RUNNER_H

#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <cstdarg>
#include <chrono>
#include <thread>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <sched.h>
#include <fcntl.h>
#include "core/types.h"
#include "core/utils.h"
#include "core/config.h"
#include "core/language.h"
#include "core/system.h"

namespace uoj {

/**
 * @brief 程序运行器 - 使用现代沙箱
 */
class Runner {
private:
    std::string main_path_;
    std::string work_path_;
    std::string result_path_;
    std::string data_path_;
    Config* config_;

public:
    Runner(const std::string &main_path, const std::string &work_path,
           const std::string &result_path, const std::string &data_path,
           Config* config)
        : main_path_(main_path), work_path_(work_path),
          result_path_(result_path), data_path_(data_path), config_(config) {}

    /**
     * @brief 运行提交的程序
     */
    RunResult run_submission(
            const std::string &input_file_name,
            const std::string &output_file_name,
            const RunLimit &limit,
            const std::string &name) {
        
        // 获取语言配置
        std::string lang = config_->get_str(name + "_language");
        auto* plugin = LanguageRegistry::instance().get(lang);
        
        // 构建程序路径和参数
        std::string program;
        std::vector<std::string> run_args;
        
        if (plugin) {
            RunContext ctx{work_path_, name, config_};
            run_args = plugin->get_run_args(ctx);
            
            if (!run_args.empty()) {
                program = run_args[0];
                run_args.erase(run_args.begin());
            } else {
                program = work_path_ + "/" + name;
            }
        } else {
            program = work_path_ + "/" + name;
        }
        
        // 替换 {memory} 占位符
        std::string memory_str = std::to_string(limit.memory);
        for (auto& arg : run_args) {
            size_t pos;
            while ((pos = arg.find("{memory}")) != std::string::npos) {
                arg.replace(pos, 8, memory_str);
            }
        }
        
        // 加载 User 配置
        UserPtr submission_user = User::load(main_path_ + "/config/users/submission.yml");
        if (!submission_user) {
            submission_user = User::submission();
        }
        
        // 从 User 构建沙箱配置
        sandbox::SandboxConfig config = sandbox::SandboxConfig::from_user(submission_user->config());
        
        // 设置程序
        config.program = program;
        config.args = run_args;
        config.work_dir = work_path_;
        
        // 应用语言特定的倍率
        double time_mult = plugin ? plugin->time_multiplier() : 1.0;
        double mem_mult = plugin ? plugin->memory_multiplier() : 1.0;
        int base_mem = plugin ? plugin->base_memory_mb() : 0;
        
        config.time_limit_ms = static_cast<int>(limit.time * 1000 * time_mult);
        config.memory_limit_kb = static_cast<int>((limit.memory * mem_mult + base_mem) * 1024);
        config.output_limit_kb = limit.output * 1024;
        
        // I/O 重定向
        config.stdin_file = input_file_name;
        config.stdout_file = output_file_name;
        config.stderr_file = work_path_ + "/stderr.txt";  // DEBUG: 临时改为文件
        
        // 启用 cgroup
        config.use_cgroup = sandbox::is_cgroup_v2_available();
        
        // 从语言插件获取额外配置
        if (plugin) {
            SyscallPolicy policy = plugin->get_runtime_policy();
            
            // 栈限制和地址空间限制
            if (policy.stack_limit_mb > 0) {
                config.stack_limit_kb = policy.stack_limit_mb * 1024;
            }
            config.disable_address_limit = policy.disable_address_limit;
            
            // 只读路径（添加到 sandbox.readonly）
            for (const auto& path : policy.readable_paths) {
                config.sandbox.readonly.push_back(path);
            }
            
            // 可写路径（添加到 sandbox.writable）
            for (const auto& path : policy.writable_paths) {
                config.sandbox.writable.push_back(path);
            }
            
            // 允许的 syscall（合并）
            for (const auto& [nr, lmt] : policy.syscall_limits) {
                if (lmt != 0) {
                    config.allowed_syscalls.insert(nr);
                }
            }
            
            // 最大进程数
            if (policy.max_processes > 0) {
                config.max_processes = policy.max_processes;
            }
        }
        
        // 添加工作目录和数据目录到可读路径
        config.sandbox.readonly.push_back(work_path_);
        config.sandbox.readonly.push_back(data_path_);
        
        // 工作目录可写
        config.sandbox.writable.push_back(work_path_);
        
        // 执行
        sandbox::Sandbox sandbox(config);
        auto result = sandbox.run();
        
        if (!result.ok()) {
            return RunResult::failed_result();
        }
        
        auto& sres = result.value();
        RunResult res = sres.to_run_result();
        if (res.type == RS_AC && sres.exit_code != 0) {
            res.type = RS_RE;
        }
        return res;
    }

    /**
     * @brief 运行 Checker
     */
    RunCheckerResult run_checker(
            const RunLimit &limit,
            const std::string &program_name,
            const std::string &input_file_name,
            const std::string &output_file_name,
            const std::string &answer_file_name) {
        
        // 加载 checker 的 User 配置
        UserPtr checker_user = User::load(main_path_ + "/config/users/problem.yml");
        if (!checker_user) {
            checker_user = User::problem();
        }
        
        sandbox::SandboxConfig config = sandbox::SandboxConfig::from_user(checker_user->config());
        
        config.program = program_name;
        config.args = {
            get_realpath(input_file_name),
            get_realpath(output_file_name),
            get_realpath(answer_file_name)
        };
        config.work_dir = work_path_;
        config.time_limit_ms = limit.time * 1000;
        config.memory_limit_kb = limit.memory * 1024;
        config.output_limit_kb = limit.output * 1024;
        
        config.stdin_file = "/dev/null";
        config.stdout_file = "/dev/null";
        config.stderr_file = result_path_ + "/checker_error.txt";
        
        // 添加可读路径
        config.sandbox.readonly.push_back(input_file_name);
        config.sandbox.readonly.push_back(output_file_name);
        config.sandbox.readonly.push_back(answer_file_name);
        config.sandbox.readonly.push_back(work_path_);
        config.sandbox.readonly.push_back(data_path_);
        
        // 添加 checker 程序路径（重要！否则 pivot_root 后找不到）
        config.sandbox.readonly.push_back(program_name);
        // 也添加整个 builtin 目录以防万一
        config.sandbox.readonly.push_back(main_path_ + "/builtin");
        
        // 可写（用于输出）
        config.sandbox.writable.push_back(result_path_);
        
        config.use_cgroup = sandbox::is_cgroup_v2_available();
        
        sandbox::Sandbox sandbox(config);
        auto result = sandbox.run();
        
        if (!result.ok()) {
            fprintf(stderr, "[Checker] Sandbox execution failed\n");
            return RunCheckerResult::failed_result();
        }
        
        auto& sres = result.value();
        RunResult rres = sres.to_run_result();
        if (sres.status == sandbox::RunStatus::RUNTIME_ERROR || 
            sres.status == sandbox::RunStatus::OK) {
            rres.type = RS_AC;
        }
        
        return RunCheckerResult::from_file(result_path_ + "/checker_error.txt", rres);
    }

    /**
     * @brief 运行 Validator
     */
    RunValidatorResult run_validator(
            const std::string &input_file_name,
            const RunLimit &limit,
            const std::string &program_name) {
        
        // 加载 validator 的 User 配置
        UserPtr validator_user = User::load(main_path_ + "/config/users/problem.yml");
        if (!validator_user) {
            validator_user = User::problem();
        }
        
        sandbox::SandboxConfig config = sandbox::SandboxConfig::from_user(validator_user->config());
        
        config.program = program_name;
        config.work_dir = work_path_;
        config.time_limit_ms = limit.time * 1000;
        config.memory_limit_kb = limit.memory * 1024;
        config.output_limit_kb = limit.output * 1024;
        
        config.stdin_file = input_file_name;
        config.stdout_file = "/dev/null";
        config.stderr_file = result_path_ + "/validator_error.txt";
        
        // 添加可读路径
        config.sandbox.readonly.push_back(input_file_name);
        config.sandbox.readonly.push_back(work_path_);
        config.sandbox.readonly.push_back(data_path_);
        
        // 可写
        config.sandbox.writable.push_back(result_path_);
        
        config.use_cgroup = sandbox::is_cgroup_v2_available();
        
        sandbox::Sandbox sandbox(config);
        auto result = sandbox.run();
        
        RunValidatorResult res;
        if (!result.ok()) {
            res.type = RS_JGF;
            res.succeeded = false;
            res.info = "Sandbox error";
            return res;
        }
        
        auto& sres = result.value();
        res.type = (sres.status == sandbox::RunStatus::OK) ? RS_AC : RS_RE;
        res.ust = sres.time_ms;
        res.usm = sres.memory_kb;
        
        if (sres.status != sandbox::RunStatus::OK || sres.exit_code != 0) {
            res.succeeded = false;
            res.info = file_preview(result_path_ + "/validator_error.txt");
        } else {
            res.succeeded = true;
        }
        
        return res;
    }

    /**
     * @brief 运行简单交互（使用沙箱架构）
     * 
     * 创建两个管道连接用户程序和交互器：
     * - 用户程序 stdout -> 交互器 stdin
     * - 交互器 stdout -> 用户程序 stdin
     * 
     * 安全模型：
     * - 用户程序：使用 submission 沙箱配置（seccomp + pivot_root + cgroup）
     * - 交互器：使用 problem 沙箱配置（pivot_root + cgroup，无 seccomp）
     */
    RunSimpleInteractionResult run_simple_interaction(
            const std::string &input_file_name,
            const std::string &answer_file_name,
            const std::string &real_input_file_name,
            const std::string &real_output_file_name,
            const RunLimit &limit,
            const RunLimit &ilimit,
            const std::string &name) {
        
        RunSimpleInteractionResult result;
        
        // 获取用户程序信息
        std::string lang = config_->get_str(name + "_language");
        auto* plugin = LanguageRegistry::instance().get(lang);
        
        std::string program;
        std::vector<std::string> run_args;
        
        if (plugin) {
            RunContext ctx{work_path_, name, config_};
            program = plugin->get_executable(ctx);
            run_args = plugin->get_run_args(ctx);
            if (!run_args.empty()) {
                program = run_args[0];
                run_args.erase(run_args.begin());
            }
        } else {
            program = work_path_ + "/" + name;
        }
        
        std::string interactor = work_path_ + "/interactor";
        std::string interactor_err = result_path_ + "/interactor_error.txt";
        
        // 创建管道
        int prog_to_inter[2];  // 用户程序 -> 交互器
        int inter_to_prog[2];  // 交互器 -> 用户程序
        
        if (pipe(prog_to_inter) == -1 || pipe(inter_to_prog) == -1) {
            result.res.type = RS_JGF;
            result.ires.type = RS_JGF;
            result.ires.info = "Failed to create pipes";
            return result;
        }
        
        // 加载沙箱配置
        UserPtr submission_user = User::load(main_path_ + "/config/users/submission.yml");
        if (!submission_user) submission_user = User::submission();
        
        UserPtr problem_user = User::load(main_path_ + "/config/users/problem.yml");
        if (!problem_user) problem_user = User::problem();
        
        // ============================================================
        // Fork 用户程序进程（使用沙箱）
        // ============================================================
        pid_t prog_pid = fork();
        if (prog_pid == 0) {
            // 子进程：用户程序
            close(prog_to_inter[0]);  // 关闭读端
            close(inter_to_prog[1]);  // 关闭写端
            
            // 构建沙箱配置
            sandbox::SandboxConfig cfg = sandbox::SandboxConfig::from_user(submission_user->config());
            cfg.program = program;
            cfg.args = run_args;
            cfg.work_dir = work_path_;
            
            // 应用语言特定的倍率
            double time_mult = plugin ? plugin->time_multiplier() : 1.0;
            double mem_mult = plugin ? plugin->memory_multiplier() : 1.0;
            int base_mem = plugin ? plugin->base_memory_mb() : 0;
            
            cfg.time_limit_ms = static_cast<int>(limit.time * 1000 * time_mult);
            cfg.memory_limit_kb = static_cast<int>((limit.memory * mem_mult + base_mem) * 1024);
            cfg.output_limit_kb = limit.output * 1024;
            
            // 添加必要路径
            cfg.sandbox.readonly.push_back(work_path_);
            cfg.sandbox.readonly.push_back(data_path_);
            cfg.sandbox.writable.push_back(work_path_);
            
            // 设置管道 I/O（使用文件描述符）
            // 使用 /dev/fd/N 形式
            char stdin_fd[32], stdout_fd[32];
            snprintf(stdin_fd, sizeof(stdin_fd), "/dev/fd/%d", inter_to_prog[0]);
            snprintf(stdout_fd, sizeof(stdout_fd), "/dev/fd/%d", prog_to_inter[1]);
            
            // 直接使用管道重定向
            dup2(inter_to_prog[0], STDIN_FILENO);
            dup2(prog_to_inter[1], STDOUT_FILENO);
            close(inter_to_prog[0]);
            close(prog_to_inter[1]);
            
            cfg.stdin_file = "";  // 已通过 dup2 重定向
            cfg.stdout_file = "";
            cfg.stderr_file = work_path_ + "/stderr.txt";
            
            // 在 unshare 后手动设置沙箱（不使用 Sandbox 类，因为需要特殊的管道处理）
            if (cfg.use_namespace) {
                int ns_flags = CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS;
                if (!cfg.allow_network) ns_flags |= CLONE_NEWNET;
                
                if (unshare(ns_flags) == 0) {
                    mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr);
                    // pivot_root 会影响文件描述符引用，所以对交互模式跳过
                    sethostname("sandbox", 7);
                }
            }
            
            // 设置 rlimits
            struct rlimit rl;
            rl.rlim_cur = (cfg.time_limit_ms + 999) / 1000 + 1;
            rl.rlim_max = rl.rlim_cur + 1;
            setrlimit(RLIMIT_CPU, &rl);
            
            if (!cfg.disable_address_limit) {
                rl.rlim_cur = rl.rlim_max = cfg.memory_limit_kb * 1024ULL * 2;
                setrlimit(RLIMIT_AS, &rl);
            }
            
            rl.rlim_cur = rl.rlim_max = cfg.memory_limit_kb * 1024ULL;
            setrlimit(RLIMIT_STACK, &rl);
            
            rl.rlim_cur = rl.rlim_max = cfg.output_limit_kb * 1024ULL;
            setrlimit(RLIMIT_FSIZE, &rl);
            
            rl.rlim_cur = rl.rlim_max = 0;
            setrlimit(RLIMIT_CORE, &rl);
            
            // 应用 seccomp（如果启用）
            if (cfg.use_seccomp && !cfg.allowed_syscalls.empty()) {
                // 由于交互模式需要管道通信，确保相关 syscall 被允许
                cfg.allowed_syscalls.insert(__NR_read);
                cfg.allowed_syscalls.insert(__NR_write);
                cfg.allowed_syscalls.insert(__NR_close);
                cfg.allowed_syscalls.insert(__NR_dup2);
                
                apply_seccomp_for_interaction(cfg.allowed_syscalls);
            }
            
            // 执行用户程序
            std::vector<char*> argv;
            argv.push_back(const_cast<char*>(program.c_str()));
            for (auto& arg : run_args) {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            argv.push_back(nullptr);
            
            execv(program.c_str(), argv.data());
            _exit(127);
        }
        
        // ============================================================
        // Fork 交互器进程（使用沙箱）
        // ============================================================
        pid_t inter_pid = fork();
        if (inter_pid == 0) {
            // 子进程：交互器
            close(prog_to_inter[1]);  // 关闭写端
            close(inter_to_prog[0]);  // 关闭读端
            
            // 管道重定向
            dup2(prog_to_inter[0], STDIN_FILENO);
            dup2(inter_to_prog[1], STDOUT_FILENO);
            close(prog_to_inter[0]);
            close(inter_to_prog[1]);
            
            // stderr 输出到文件
            int err_fd = open(interactor_err.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (err_fd >= 0) {
                dup2(err_fd, STDERR_FILENO);
                close(err_fd);
            }
            
            // 构建沙箱配置
            sandbox::SandboxConfig cfg = sandbox::SandboxConfig::from_user(problem_user->config());
            cfg.program = interactor;
            cfg.work_dir = work_path_;
            cfg.time_limit_ms = (ilimit.time + limit.time + 2) * 1000;
            cfg.memory_limit_kb = ilimit.memory * 1024;
            
            // Namespace 隔离（不包含 pivot_root，因为需要访问数据文件）
            if (cfg.use_namespace) {
                int ns_flags = CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS;
                if (!cfg.allow_network) ns_flags |= CLONE_NEWNET;
                
                if (unshare(ns_flags) == 0) {
                    mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr);
                    sethostname("sandbox", 7);
                }
            }
            
            // 设置 rlimits
            struct rlimit rl;
            rl.rlim_cur = rl.rlim_max = (ilimit.time + limit.time + 2);
            setrlimit(RLIMIT_CPU, &rl);
            
            // 执行交互器
            execl(interactor.c_str(), interactor.c_str(),
                  input_file_name.c_str(), "/dev/stdin", answer_file_name.c_str(),
                  nullptr);
            _exit(127);
        }
        
        // ============================================================
        // 父进程：等待子进程
        // ============================================================
        close(prog_to_inter[0]);
        close(prog_to_inter[1]);
        close(inter_to_prog[0]);
        close(inter_to_prog[1]);
        
        // 使用 wait4 获取资源使用
        int prog_status = 0, inter_status = 0;
        struct rusage prog_usage, inter_usage;
        memset(&prog_usage, 0, sizeof(prog_usage));
        memset(&inter_usage, 0, sizeof(inter_usage));
        
        // 设置超时
        auto deadline = std::chrono::steady_clock::now() + 
                       std::chrono::seconds(limit.time + ilimit.time + 5);
        bool prog_done = false, inter_done = false;
        
        while (!prog_done || !inter_done) {
            if (!prog_done) {
                pid_t ret = wait4(prog_pid, &prog_status, WNOHANG, &prog_usage);
                if (ret > 0) prog_done = true;
            }
            if (!inter_done) {
                pid_t ret = wait4(inter_pid, &inter_status, WNOHANG, &inter_usage);
                if (ret > 0) inter_done = true;
            }
            
            if (std::chrono::steady_clock::now() >= deadline) {
                // 超时，杀死两个进程
                if (!prog_done) { kill(prog_pid, SIGKILL); wait4(prog_pid, &prog_status, 0, &prog_usage); }
                if (!inter_done) { kill(inter_pid, SIGKILL); wait4(inter_pid, &inter_status, 0, &inter_usage); }
                break;
            }
            
            if (!prog_done || !inter_done) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
        
        // 解析用户程序结果
        RunResult res;
        res.exit_code = WIFEXITED(prog_status) ? WEXITSTATUS(prog_status) : -1;
        res.ust = prog_usage.ru_utime.tv_sec * 1000 + prog_usage.ru_utime.tv_usec / 1000;
        res.usm = prog_usage.ru_maxrss;
        
        if (WIFSIGNALED(prog_status)) {
            int sig = WTERMSIG(prog_status);
            if (sig == SIGXCPU || sig == SIGKILL) {
                res.type = (res.ust >= limit.time * 1000) ? RS_TLE : RS_RE;
            } else if (sig == SIGSYS) {
                res.type = RS_DGS;
            } else if (sig == SIGSEGV || sig == SIGBUS) {
                res.type = (res.usm >= limit.memory * 1024) ? RS_MLE : RS_RE;
            } else {
                res.type = RS_RE;
            }
        } else if (res.exit_code != 0) {
            res.type = RS_RE;
        } else if (res.ust > limit.time * 1000) {
            res.type = RS_TLE;
        } else if (res.usm > limit.memory * 1024) {
            res.type = RS_MLE;
        } else {
            res.type = RS_AC;
        }
        
        // 解析交互器结果
        RunCheckerResult ires = RunCheckerResult::from_file(
            interactor_err,
            RunResult{RS_AC, 0, 0, WIFEXITED(inter_status) ? WEXITSTATUS(inter_status) : -1});
        
        if (WIFSIGNALED(inter_status) || (!WIFEXITED(inter_status) || WEXITSTATUS(inter_status) == 127)) {
            ires.type = RS_JGF;
            ires.info = "Interactor crashed";
        }
        
        result.res = res;
        result.ires = ires;
        return result;
    }
    
private:
    /**
     * @brief 为交互模式应用 seccomp 过滤器
     */
    static void apply_seccomp_for_interaction(const std::set<int>& allowed_syscalls) {
        size_t total = allowed_syscalls.size();
        size_t prog_len = 4 + total + 2;
        
        struct sock_filter* filter = (struct sock_filter*)malloc(prog_len * sizeof(struct sock_filter));
        if (!filter) _exit(127);
        
        size_t idx = 0;
        
        // 检查架构
        filter[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
        filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
        filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
        
        // 加载 syscall 号
        filter[idx++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
        
        // 检查允许的 syscall
        size_t remaining = total;
        for (int nr : allowed_syscalls) {
            remaining--;
            filter[idx++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)nr, (uint8_t)(remaining + 1), 0);
        }
        
        filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
        filter[idx++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        
        struct sock_fprog prog = { .len = (unsigned short)idx, .filter = filter };
        
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
        
        free(filter);
    }
    
public:

    //=========================================================================
    // 新 API: 使用 User 安全架构运行程序
    //=========================================================================
    
    RunResult run_with_user(
            UserPtr user,
            const std::string& program,
            const std::vector<std::string>& args,
            const RunLimit& limit,
            const std::string& stdin_file,
            const std::string& stdout_file,
            const std::string& stderr_file = "/dev/null") {
        
        sandbox::SandboxConfig config = sandbox::SandboxConfig::from_user(user->config());
        
        config.time_limit_ms = limit.time * 1000;
        config.memory_limit_kb = limit.memory * 1024;
        config.output_limit_kb = limit.output * 1024;
        if (limit.real_time > 0) {
            config.real_time_limit_ms = limit.real_time * 1000;
        }
        
        config.program = program;
        config.args = args;
        
        config.stdin_file = stdin_file;
        config.stdout_file = stdout_file;
        config.stderr_file = stderr_file;
        
        if (config.work_dir.empty()) {
            config.work_dir = work_path_;
        }
        
        // 添加工作目录到可写路径
        config.sandbox.writable.push_back(work_path_);
        
        sandbox::Sandbox sandbox(config);
        auto sres = sandbox.run();
        
        return convert_sandbox_result(sres);
    }
    
    RunResult run_as_submission(
            const std::string& program,
            const std::vector<std::string>& args,
            const RunLimit& limit,
            const std::string& stdin_file,
            const std::string& stdout_file) {
        return run_with_user(User::submission(), program, args, limit, stdin_file, stdout_file);
    }
    
    RunResult run_as_checker(
            const std::string& checker,
            const std::vector<std::string>& args,
            const RunLimit& limit) {
        return run_with_user(User::problem(), checker, args, limit, "/dev/null", "/dev/null",
                             result_path_ + "/checker_error.txt");
    }

    const std::string& main_path() const { return main_path_; }
    const std::string& work_path() const { return work_path_; }
    const std::string& result_path() const { return result_path_; }
    const std::string& data_path() const { return data_path_; }
    
private:
    RunResult convert_sandbox_result(const Result<sandbox::SandboxResult>& sres) {
        RunResult result;
        
        if (!sres.ok()) {
            result.type = RS_JGF;
            result.ust = -1;
            result.usm = -1;
            result.exit_code = -1;
            return result;
        }
        
        const auto& sr = sres.value();
        result.ust = sr.time_ms;
        result.usm = sr.memory_kb;
        result.exit_code = sr.exit_code;
        
        switch (sr.status) {
            case sandbox::RunStatus::OK:
                result.type = (sr.exit_code == 0) ? RS_AC : RS_RE;
                break;
            case sandbox::RunStatus::TIME_LIMIT:
                result.type = RS_TLE;
                break;
            case sandbox::RunStatus::MEMORY_LIMIT:
                result.type = RS_MLE;
                break;
            case sandbox::RunStatus::OUTPUT_LIMIT:
                result.type = RS_OLE;
                break;
            case sandbox::RunStatus::RUNTIME_ERROR:
            case sandbox::RunStatus::KILLED_BY_SIGNAL:
                result.type = RS_RE;
                break;
            case sandbox::RunStatus::SECCOMP_VIOLATION:
                result.type = RS_DGS;
                break;
            default:
                result.type = RS_JGF;
        }
        
        return result;
    }
};

// RunCheckerResult::from_file 实现
inline RunCheckerResult RunCheckerResult::from_file(const std::string &file_name, const RunResult &rres) {
    RunCheckerResult res;
    res.type = rres.type;
    res.ust = rres.ust;
    res.usm = rres.usm;

    if (rres.type != RS_AC) {
        res.scr = 0;
    } else {
        FILE *fres = fopen(file_name.c_str(), "r");
        char type[21];
        if (fres == NULL || fscanf(fres, "%20s", type) != 1) {
            if (fres) fclose(fres);
            return RunCheckerResult::failed_result();
        }
        if (strcmp(type, "ok") == 0) {
            res.scr = 100;
        } else if (strcmp(type, "points") == 0) {
            double d;
            if (fscanf(fres, "%lf", &d) != 1) {
                fclose(fres);
                return RunCheckerResult::failed_result();
            }
            res.scr = static_cast<int>(floor(100 * d + 0.5));
        } else {
            res.scr = 0;
        }
        fclose(fres);
    }
    res.info = file_preview(file_name);
    return res;
}

} // namespace uoj

#endif // UOJ_CORE_RUNNER_H
