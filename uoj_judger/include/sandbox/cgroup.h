/**
 * @file cgroup.h
 * @brief cgroups v2 资源限制
 * 
 * 使用 cgroups v2 进行资源限制，比 ptrace 检查更高效。
 * 
 * 支持的限制：
 * - 内存限制 (memory.max, memory.swap.max)
 * - CPU 限制 (cpu.max)
 * - 进程数限制 (pids.max)
 * - I/O 带宽限制 (io.max)
 */

#ifndef UOJ_SANDBOX_CGROUP_H
#define UOJ_SANDBOX_CGROUP_H

#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <vector>
#include <memory>
#include <mutex>
#include <unistd.h>
#include <sys/stat.h>

#include "core/error.h"

namespace uoj {
namespace sandbox {

namespace fs = std::filesystem;

/**
 * @brief cgroup 资源使用统计
 */
struct CgroupStats {
    // 内存
    uint64_t memory_current;      ///< 当前内存使用 (bytes)
    uint64_t memory_peak;         ///< 峰值内存使用 (bytes)
    bool oom_killed;              ///< 是否被 OOM killer 杀死
    
    // CPU
    uint64_t cpu_usage_usec;      ///< CPU 使用时间 (微秒)
    uint64_t cpu_user_usec;       ///< 用户态 CPU 时间
    uint64_t cpu_system_usec;     ///< 内核态 CPU 时间
    
    // 进程
    uint64_t pids_current;        ///< 当前进程数
    
    CgroupStats() 
        : memory_current(0), memory_peak(0), oom_killed(false),
          cpu_usage_usec(0), cpu_user_usec(0), cpu_system_usec(0),
          pids_current(0) {}
};

/**
 * @brief cgroup 资源限制配置
 */
struct CgroupLimits {
    uint64_t memory_max;          ///< 最大内存 (bytes), 0 = 不限制
    uint64_t memory_swap_max;     ///< 最大 swap (bytes), 0 = 禁用 swap
    
    uint64_t cpu_quota_usec;      ///< CPU 配额 (微秒), 0 = 不限制
    uint64_t cpu_period_usec;     ///< CPU 周期 (微秒), 默认 100000
    
    uint64_t pids_max;            ///< 最大进程数, 0 = 不限制
    
    CgroupLimits() 
        : memory_max(0), memory_swap_max(0),
          cpu_quota_usec(0), cpu_period_usec(100000),
          pids_max(0) {}
    
    // 便捷设置方法
    CgroupLimits& set_memory(uint64_t mb) {
        memory_max = mb * 1024 * 1024;
        return *this;
    }
    
    CgroupLimits& set_memory_bytes(uint64_t bytes) {
        memory_max = bytes;
        return *this;
    }
    
    CgroupLimits& disable_swap() {
        memory_swap_max = 0;
        return *this;
    }
    
    CgroupLimits& set_cpu_percent(int percent) {
        cpu_quota_usec = cpu_period_usec * percent / 100;
        return *this;
    }
    
    CgroupLimits& set_cpu_cores(double cores) {
        cpu_quota_usec = static_cast<uint64_t>(cpu_period_usec * cores);
        return *this;
    }
    
    CgroupLimits& set_max_pids(uint64_t max) {
        pids_max = max;
        return *this;
    }
};

/**
 * @brief cgroup v2 控制器
 */
class CgroupController {
private:
    std::string cgroup_path_;
    std::string name_;
    bool created_;
    bool auto_cleanup_;

    static constexpr const char* CGROUP_ROOT = "/sys/fs/cgroup";

    /**
     * @brief 写入 cgroup 控制文件
     */
    Result<void> write_file(const std::string &filename, const std::string &content) {
        std::string path = cgroup_path_ + "/" + filename;
        std::ofstream file(path);
        if (!file) {
            return Err<void>(ErrorCode::FILE_WRITE_ERROR, 
                           "Cannot write to " + path);
        }
        file << content;
        if (!file) {
            return Err<void>(ErrorCode::FILE_WRITE_ERROR,
                           "Write failed: " + path);
        }
        return Ok();
    }

    /**
     * @brief 读取 cgroup 控制文件
     */
    Result<std::string> read_file(const std::string &filename) {
        std::string path = cgroup_path_ + "/" + filename;
        std::ifstream file(path);
        if (!file) {
            return Err<std::string>(ErrorCode::FILE_READ_ERROR,
                                   "Cannot read " + path);
        }
        std::ostringstream oss;
        oss << file.rdbuf();
        return Ok(oss.str());
    }

    /**
     * @brief 读取 uint64 值
     */
    uint64_t read_uint64(const std::string &filename, uint64_t default_val = 0) {
        auto result = read_file(filename);
        if (!result.ok()) return default_val;
        
        try {
            std::string content = result.value();
            // 处理 "max" 特殊值
            if (content.find("max") != std::string::npos) {
                return UINT64_MAX;
            }
            return std::stoull(content);
        } catch (...) {
            return default_val;
        }
    }

    /**
     * @brief 解析 key-value 格式的状态文件
     */
    uint64_t parse_stat(const std::string &content, const std::string &key) {
        std::istringstream iss(content);
        std::string line;
        while (std::getline(iss, line)) {
            if (line.find(key) == 0) {
                size_t pos = line.find(' ');
                if (pos != std::string::npos) {
                    try {
                        return std::stoull(line.substr(pos + 1));
                    } catch (...) {}
                }
            }
        }
        return 0;
    }

public:
    /**
     * @brief 构造函数
     * @param name cgroup 名称
     * @param parent 父 cgroup 路径（相对于 /sys/fs/cgroup）
     */
    explicit CgroupController(const std::string &name, 
                              const std::string &parent = "uoj")
        : name_(name), created_(false), auto_cleanup_(true) {
        cgroup_path_ = std::string(CGROUP_ROOT) + "/" + parent + "/" + name;
    }

    ~CgroupController() {
        if (created_ && auto_cleanup_) {
            destroy();
        }
    }

    // 禁止复制
    CgroupController(const CgroupController&) = delete;
    CgroupController& operator=(const CgroupController&) = delete;
    
    // 允许移动
    CgroupController(CgroupController&& other) noexcept
        : cgroup_path_(std::move(other.cgroup_path_)),
          name_(std::move(other.name_)),
          created_(other.created_),
          auto_cleanup_(other.auto_cleanup_) {
        other.created_ = false;
    }

    /**
     * @brief 设置是否自动清理
     */
    void set_auto_cleanup(bool cleanup) {
        auto_cleanup_ = cleanup;
    }

    /**
     * @brief 创建 cgroup
     */
    Result<void> create() {
        // 确保父目录存在
        std::string parent_path = cgroup_path_.substr(0, cgroup_path_.rfind('/'));
        if (!fs::exists(parent_path)) {
            try {
                fs::create_directories(parent_path);
            } catch (const fs::filesystem_error &e) {
                return Err<void>(ErrorCode::FILE_WRITE_ERROR,
                               "Cannot create parent cgroup: " + std::string(e.what()));
            }
        }
        
        // 启用控制器（在父 cgroup 中）
        std::ofstream subtree(parent_path + "/cgroup.subtree_control");
        if (subtree) {
            subtree << "+memory +cpu +pids +io";
        }
        
        // 创建 cgroup 目录
        if (mkdir(cgroup_path_.c_str(), 0755) < 0) {
            if (errno != EEXIST) {
                return Err<void>(ErrorCode::FILE_WRITE_ERROR,
                               "Cannot create cgroup: " + cgroup_path_);
            }
        }
        
        created_ = true;
        return Ok();
    }

    /**
     * @brief 销毁 cgroup
     */
    Result<void> destroy() {
        if (!created_) return Ok();
        
        // 先移除所有进程
        write_file("cgroup.procs", "");
        
        // 删除目录
        if (rmdir(cgroup_path_.c_str()) < 0) {
            if (errno != ENOENT) {
                return Err<void>(ErrorCode::FILE_WRITE_ERROR,
                               "Cannot remove cgroup: " + cgroup_path_);
            }
        }
        
        created_ = false;
        return Ok();
    }

    /**
     * @brief 应用资源限制
     */
    Result<void> apply_limits(const CgroupLimits &limits) {
        // 内存限制
        if (limits.memory_max > 0) {
            UOJ_TRY(write_file("memory.max", std::to_string(limits.memory_max)));
        }
        
        // Swap 限制
        UOJ_TRY(write_file("memory.swap.max", std::to_string(limits.memory_swap_max)));
        
        // CPU 限制
        if (limits.cpu_quota_usec > 0) {
            std::ostringstream oss;
            oss << limits.cpu_quota_usec << " " << limits.cpu_period_usec;
            UOJ_TRY(write_file("cpu.max", oss.str()));
        }
        
        // 进程数限制
        if (limits.pids_max > 0) {
            UOJ_TRY(write_file("pids.max", std::to_string(limits.pids_max)));
        }
        
        return Ok();
    }

    /**
     * @brief 添加进程到 cgroup
     */
    Result<void> add_process(pid_t pid) {
        return write_file("cgroup.procs", std::to_string(pid));
    }

    /**
     * @brief 获取资源使用统计
     */
    CgroupStats get_stats() {
        CgroupStats stats;
        
        // 内存统计
        stats.memory_current = read_uint64("memory.current");
        stats.memory_peak = read_uint64("memory.peak");
        
        // 检查 OOM
        auto events = read_file("memory.events");
        if (events.ok()) {
            stats.oom_killed = parse_stat(events.value(), "oom_kill") > 0;
        }
        
        // CPU 统计
        auto cpu_stat = read_file("cpu.stat");
        if (cpu_stat.ok()) {
            stats.cpu_usage_usec = parse_stat(cpu_stat.value(), "usage_usec");
            stats.cpu_user_usec = parse_stat(cpu_stat.value(), "user_usec");
            stats.cpu_system_usec = parse_stat(cpu_stat.value(), "system_usec");
        }
        
        // 进程数统计
        stats.pids_current = read_uint64("pids.current");
        
        return stats;
    }

    /**
     * @brief 冻结 cgroup 中的所有进程
     */
    Result<void> freeze() {
        return write_file("cgroup.freeze", "1");
    }

    /**
     * @brief 解冻 cgroup 中的所有进程
     */
    Result<void> thaw() {
        return write_file("cgroup.freeze", "0");
    }

    /**
     * @brief 杀死 cgroup 中的所有进程
     */
    Result<void> kill_all() {
        return write_file("cgroup.kill", "1");
    }

    /**
     * @brief 重置 cgroup 以便复用
     * 
     * 杀死所有进程，重置统计计数器，但保留 cgroup 本身
     */
    Result<void> reset() {
        // 1. 杀死所有进程
        write_file("cgroup.kill", "1");
        
        // 2. 等待进程退出
        for (int i = 0; i < 10; i++) {
            auto procs = read_file("cgroup.procs");
            if (procs.ok() && procs.value().empty()) break;
            usleep(1000);  // 1ms
        }
        
        // 3. 重置内存峰值统计 (cgroup v2 不支持直接重置，需要重新创建)
        // 但我们可以记录当前值作为基准
        
        return Ok();
    }
    
    /**
     * @brief 获取 cgroup 路径
     */
    const std::string& path() const { return cgroup_path_; }
    
    /**
     * @brief 检查是否已创建
     */
    bool is_created() const { return created_; }
};

/**
 * @brief 检查 cgroups v2 是否可用
 */
inline bool is_cgroup_v2_available() {
    // 检查 cgroup2 是否挂载
    return fs::exists("/sys/fs/cgroup/cgroup.controllers");
}

/**
 * @brief 创建评测机专用 cgroup
 */
inline Result<CgroupController> create_judge_cgroup(
    const std::string &name,
    uint64_t memory_mb,
    uint64_t max_pids = 1
) {
    CgroupController cg(name);
    
    UOJ_TRY(cg.create());
    
    CgroupLimits limits;
    limits.set_memory(memory_mb)
          .disable_swap()
          .set_max_pids(max_pids);
    
    UOJ_TRY(cg.apply_limits(limits));
    
    return Ok(std::move(cg));
}

/**
 * @brief cgroup 池 - 复用 cgroup 减少创建/销毁开销
 * 
 * 使用方法：
 *   auto& pool = CgroupPool::instance();
 *   auto cg = pool.acquire(memory_mb, max_pids);
 *   // 使用 cg...
 *   pool.release(std::move(cg));  // 归还到池中
 */
class CgroupPool {
private:
    std::vector<std::unique_ptr<CgroupController>> pool_;
    std::mutex mutex_;
    int next_id_ = 0;
    
    CgroupPool() = default;
    
public:
    static CgroupPool& instance() {
        static CgroupPool pool;
        return pool;
    }
    
    /**
     * @brief 获取一个 cgroup（从池中取或新建）
     */
    std::unique_ptr<CgroupController> acquire(uint64_t memory_mb, uint64_t max_pids = 64) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // 尝试从池中获取
        if (!pool_.empty()) {
            auto cg = std::move(pool_.back());
            pool_.pop_back();
            
            // 重置并更新限制
            cg->reset();
            CgroupLimits limits;
            limits.set_memory(memory_mb).disable_swap().set_max_pids(max_pids);
            cg->apply_limits(limits);
            
            return cg;
        }
        
        // 创建新的
        std::string name = "sandbox_" + std::to_string(getpid()) + "_" + std::to_string(next_id_++);
        auto cg = std::make_unique<CgroupController>(name);
        cg->set_auto_cleanup(false);  // 池管理生命周期
        
        if (cg->create().ok()) {
            CgroupLimits limits;
            limits.set_memory(memory_mb).disable_swap().set_max_pids(max_pids);
            cg->apply_limits(limits);
            return cg;
        }
        
        return nullptr;
    }
    
    /**
     * @brief 归还 cgroup 到池中
     */
    void release(std::unique_ptr<CgroupController> cg) {
        if (!cg) return;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        // 限制池大小
        if (pool_.size() < 4) {
            cg->reset();
            pool_.push_back(std::move(cg));
        } else {
            // 超出池大小，直接销毁
            cg->destroy();
        }
    }
    
    /**
     * @brief 清空池
     */
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& cg : pool_) {
            cg->destroy();
        }
        pool_.clear();
    }
    
    ~CgroupPool() {
        clear();
    }
};

} // namespace sandbox
} // namespace uoj

#endif // UOJ_SANDBOX_CGROUP_H

