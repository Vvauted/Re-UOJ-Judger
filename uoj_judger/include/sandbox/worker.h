/**
 * @file worker.h
 * @brief 持久化沙箱工作进程
 * 
 * 创建一个持久的沙箱进程，避免每次测试点都创建新的 namespace。
 * 所有测试点在同一个隔离环境中运行，通过管道通信。
 */

#ifndef UOJ_SANDBOX_WORKER_H
#define UOJ_SANDBOX_WORKER_H

#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <chrono>
#include <mutex>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>

#include "sandbox/cgroup.h"
#include "sandbox/sandbox.h"
#include "sandbox/namespace.h"
#include "sandbox/seccomp.h"
#include "core/logger.h"

namespace uoj {
namespace sandbox {

/**
 * @brief 执行请求
 */
struct WorkerRequest {
    std::string program;
    std::vector<std::string> args;
    std::string stdin_file;
    std::string stdout_file;
    std::string stderr_file;
    int time_limit_ms = 1000;
    int memory_limit_kb = 262144;
    int output_limit_kb = 65536;
};

/**
 * @brief 执行结果
 */
struct WorkerResult {
    RunStatus status = RunStatus::OK;
    int exit_code = 0;
    int time_ms = 0;
    int memory_kb = 0;
    std::string error;
};

/**
 * @brief 持久化沙箱工作进程
 */
class SandboxWorker {
private:
    pid_t worker_pid_ = -1;
    int cmd_pipe_[2] = {-1, -1};   // 父 -> 子
    int result_pipe_[2] = {-1, -1}; // 子 -> 父
    std::unique_ptr<CgroupController> cgroup_;
    std::string work_dir_;
    bool initialized_ = false;

public:
    explicit SandboxWorker(const std::string& work_dir) 
        : work_dir_(work_dir) {}
    
    ~SandboxWorker() {
        shutdown();
    }
    
    // 禁止复制
    SandboxWorker(const SandboxWorker&) = delete;
    SandboxWorker& operator=(const SandboxWorker&) = delete;
    
    /**
     * @brief 初始化工作进程
     */
    bool init(uint64_t memory_mb = 512, uint64_t max_pids = 64) {
        if (initialized_) return true;
        
        // 创建管道
        if (pipe(cmd_pipe_) < 0 || pipe(result_pipe_) < 0) {
            LOG_ERROR << "Failed to create pipes";
            return false;
        }
        
        // 获取 cgroup
        cgroup_ = CgroupPool::instance().acquire(memory_mb, max_pids);
        
        // Fork 工作进程
        worker_pid_ = fork();
        
        if (worker_pid_ < 0) {
            LOG_ERROR << "Fork failed";
            return false;
        }
        
        if (worker_pid_ == 0) {
            // 子进程 - 工作进程
            close(cmd_pipe_[1]);     // 关闭写端
            close(result_pipe_[0]);  // 关闭读端
            
            worker_loop(cmd_pipe_[0], result_pipe_[1]);
            _exit(0);
        }
        
        // 父进程
        close(cmd_pipe_[0]);     // 关闭读端
        close(result_pipe_[1]);  // 关闭写端
        
        // 将工作进程加入 cgroup
        if (cgroup_) {
            cgroup_->add_process(worker_pid_);
        }
        
        initialized_ = true;
        return true;
    }
    
    /**
     * @brief 执行程序
     */
    WorkerResult execute(const WorkerRequest& req) {
        WorkerResult result;
        
        if (!initialized_) {
            result.status = RunStatus::INTERNAL_ERROR;
            result.error = "Worker not initialized";
            return result;
        }
        
        // 序列化请求
        std::string cmd = serialize_request(req);
        
        // 发送请求
        uint32_t len = cmd.size();
        write(cmd_pipe_[1], &len, sizeof(len));
        write(cmd_pipe_[1], cmd.data(), len);
        
        // 读取结果
        uint32_t result_len;
        if (read(result_pipe_[0], &result_len, sizeof(result_len)) != sizeof(result_len)) {
            result.status = RunStatus::INTERNAL_ERROR;
            result.error = "Failed to read result";
            return result;
        }
        
        std::string result_str(result_len, '\0');
        if (read(result_pipe_[0], &result_str[0], result_len) != (ssize_t)result_len) {
            result.status = RunStatus::INTERNAL_ERROR;
            result.error = "Failed to read result data";
            return result;
        }
        
        return deserialize_result(result_str);
    }
    
    /**
     * @brief 关闭工作进程
     */
    void shutdown() {
        if (worker_pid_ > 0) {
            // 发送退出信号
            kill(worker_pid_, SIGTERM);
            waitpid(worker_pid_, nullptr, 0);
            worker_pid_ = -1;
        }
        
        if (cmd_pipe_[1] >= 0) {
            close(cmd_pipe_[1]);
            cmd_pipe_[1] = -1;
        }
        if (result_pipe_[0] >= 0) {
            close(result_pipe_[0]);
            result_pipe_[0] = -1;
        }
        
        // 归还 cgroup
        if (cgroup_) {
            CgroupPool::instance().release(std::move(cgroup_));
        }
        
        initialized_ = false;
    }

private:
    /**
     * @brief 工作进程主循环
     */
    void worker_loop(int cmd_fd, int result_fd) {
        // 进入 namespace
        int ns_flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID;
        if (unshare(ns_flags) < 0) {
            // 如果失败，继续运行但记录警告
        }
        
        // 设置文件系统隔离
        mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr);
        
        // 主循环
        while (true) {
            uint32_t len;
            if (read(cmd_fd, &len, sizeof(len)) != sizeof(len)) {
                break;  // 管道关闭，退出
            }
            
            std::string cmd(len, '\0');
            if (read(cmd_fd, &cmd[0], len) != (ssize_t)len) {
                break;
            }
            
            // 解析并执行请求
            WorkerRequest req = deserialize_request(cmd);
            WorkerResult result = do_execute(req);
            
            // 发送结果
            std::string result_str = serialize_result(result);
            uint32_t result_len = result_str.size();
            write(result_fd, &result_len, sizeof(result_len));
            write(result_fd, result_str.data(), result_len);
        }
    }
    
    /**
     * @brief 实际执行程序
     */
    WorkerResult do_execute(const WorkerRequest& req) {
        WorkerResult result;
        
        auto start_time = std::chrono::steady_clock::now();
        
        pid_t pid = fork();
        if (pid < 0) {
            result.status = RunStatus::INTERNAL_ERROR;
            result.error = "Fork failed in worker";
            return result;
        }
        
        if (pid == 0) {
            // 子进程 - 执行用户程序
            
            // 设置资源限制
            struct rlimit rl;
            rl.rlim_cur = rl.rlim_max = (req.time_limit_ms / 1000) + 2;
            setrlimit(RLIMIT_CPU, &rl);
            
            rl.rlim_cur = rl.rlim_max = req.memory_limit_kb * 1024;
            setrlimit(RLIMIT_AS, &rl);
            
            rl.rlim_cur = rl.rlim_max = req.output_limit_kb * 1024;
            setrlimit(RLIMIT_FSIZE, &rl);
            
            // I/O 重定向
            if (!req.stdin_file.empty()) {
                int fd = open(req.stdin_file.c_str(), O_RDONLY);
                if (fd >= 0) { dup2(fd, STDIN_FILENO); close(fd); }
            }
            if (!req.stdout_file.empty()) {
                int fd = open(req.stdout_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd >= 0) { dup2(fd, STDOUT_FILENO); close(fd); }
            }
            if (!req.stderr_file.empty()) {
                int fd = open(req.stderr_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd >= 0) { dup2(fd, STDERR_FILENO); close(fd); }
            }
            
            // 执行程序
            std::vector<char*> argv;
            argv.push_back(const_cast<char*>(req.program.c_str()));
            for (const auto& arg : req.args) {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            argv.push_back(nullptr);
            
            execv(req.program.c_str(), argv.data());
            _exit(127);
        }
        
        // 父进程 - 等待子进程
        struct rusage usage;
        int status;
        
        // 设置超时
        alarm((req.time_limit_ms / 1000) + 3);
        
        if (wait4(pid, &status, 0, &usage) < 0) {
            result.status = RunStatus::INTERNAL_ERROR;
            result.error = "Wait failed";
            return result;
        }
        
        alarm(0);
        
        auto end_time = std::chrono::steady_clock::now();
        auto wall_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();
        
        // 收集结果
        result.time_ms = usage.ru_utime.tv_sec * 1000 + usage.ru_utime.tv_usec / 1000;
        result.memory_kb = usage.ru_maxrss;
        
        if (WIFEXITED(status)) {
            result.exit_code = WEXITSTATUS(status);
            result.status = (result.exit_code == 0) ? RunStatus::OK : RunStatus::RUNTIME_ERROR;
        } else if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            if (sig == SIGXCPU || sig == SIGALRM) {
                result.status = RunStatus::TIME_LIMIT;
            } else if (sig == SIGSEGV || sig == SIGBUS) {
                result.status = RunStatus::MEMORY_LIMIT;
            } else if (sig == SIGKILL) {
                result.status = RunStatus::MEMORY_LIMIT;
            } else {
                result.status = RunStatus::RUNTIME_ERROR;
            }
            result.exit_code = -sig;
        }
        
        // 检查限制
        if (result.time_ms > req.time_limit_ms) {
            result.status = RunStatus::TIME_LIMIT;
        }
        if (result.memory_kb > req.memory_limit_kb) {
            result.status = RunStatus::MEMORY_LIMIT;
        }
        
        return result;
    }
    
    // 简单的序列化/反序列化
    std::string serialize_request(const WorkerRequest& req) {
        std::ostringstream oss;
        oss << req.program << "\n"
            << req.stdin_file << "\n"
            << req.stdout_file << "\n"
            << req.stderr_file << "\n"
            << req.time_limit_ms << "\n"
            << req.memory_limit_kb << "\n"
            << req.output_limit_kb << "\n"
            << req.args.size() << "\n";
        for (const auto& arg : req.args) {
            oss << arg << "\n";
        }
        return oss.str();
    }
    
    WorkerRequest deserialize_request(const std::string& str) {
        WorkerRequest req;
        std::istringstream iss(str);
        std::getline(iss, req.program);
        std::getline(iss, req.stdin_file);
        std::getline(iss, req.stdout_file);
        std::getline(iss, req.stderr_file);
        iss >> req.time_limit_ms >> req.memory_limit_kb >> req.output_limit_kb;
        size_t argc;
        iss >> argc;
        iss.ignore();
        for (size_t i = 0; i < argc; i++) {
            std::string arg;
            std::getline(iss, arg);
            req.args.push_back(arg);
        }
        return req;
    }
    
    std::string serialize_result(const WorkerResult& res) {
        std::ostringstream oss;
        oss << static_cast<int>(res.status) << "\n"
            << res.exit_code << "\n"
            << res.time_ms << "\n"
            << res.memory_kb << "\n"
            << res.error;
        return oss.str();
    }
    
    WorkerResult deserialize_result(const std::string& str) {
        WorkerResult res;
        std::istringstream iss(str);
        int status;
        iss >> status >> res.exit_code >> res.time_ms >> res.memory_kb;
        iss.ignore();
        std::getline(iss, res.error);
        res.status = static_cast<RunStatus>(status);
        return res;
    }
};

/**
 * @brief 工作进程池
 */
class WorkerPool {
private:
    std::string work_dir_;
    std::unique_ptr<SandboxWorker> worker_;
    std::mutex mutex_;
    
public:
    explicit WorkerPool(const std::string& work_dir) : work_dir_(work_dir) {}
    
    /**
     * @brief 获取工作进程（复用现有或创建新的）
     */
    SandboxWorker* get() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!worker_ || !worker_->init()) {
            worker_ = std::make_unique<SandboxWorker>(work_dir_);
            if (!worker_->init()) {
                return nullptr;
            }
        }
        return worker_.get();
    }
    
    /**
     * @brief 重置工作进程
     */
    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (worker_) {
            worker_->shutdown();
            worker_.reset();
        }
    }
};

} // namespace sandbox
} // namespace uoj

#endif // UOJ_SANDBOX_WORKER_H

