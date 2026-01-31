/**
 * @file cgroup.h
 * @brief cgroups v2 资源限制
 * 
 * 使用 cgroups v2 进行资源限制，比 ptrace 检查更高效。
 * 
 * 架构设计（遵循 cgroup v2 "no internal processes" 规则）：
 * 
 * 当通过 systemd-run --scope --property=Delegate=yes 启动时：
 *   /sys/fs/cgroup/system.slice/run-XXXXX.scope/  （被委派）
 *   ├── judger/          ← main_judger 进程移动到这里
 *   └── sandbox/         ← 沙箱 cgroup 池
 *       ├── box_0/
 *       ├── box_1/
 *       └── ...
 * 
 * 当在 Docker 容器中运行时：
 *   /sys/fs/cgroup/      （容器内的根）
 *   ├── judger/          ← main_judger 进程
 *   └── sandbox/         ← 沙箱 cgroup 池
 *       ├── box_0/
 *       └── ...
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
#include <sys/vfs.h>
#include <linux/magic.h>

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
 * @brief 获取当前进程的 cgroup 路径
 * 
 * 读取 /proc/self/cgroup 来确定当前进程所在的 cgroup。
 * 在 cgroup v2 中，格式为 "0::/path/to/cgroup"
 * 
 * @return cgroup 路径（相对于 /sys/fs/cgroup）
 */
inline std::string get_self_cgroup_path() {
    std::ifstream cgroup_file("/proc/self/cgroup");
    if (!cgroup_file) {
        return "";
    }
    
    std::string line;
    while (std::getline(cgroup_file, line)) {
        // cgroup v2 格式: "0::/path"
        if (line.substr(0, 3) == "0::") {
            return line.substr(3);
        }
    }
    
    return "";
}

/**
 * @brief cgroup v2 控制器
 */
class CgroupController {
private:
    std::string cgroup_path_;
    std::string name_;
    bool created_;
    bool auto_cleanup_;

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
     * @param parent_path 父 cgroup 的完整路径（绝对路径）
     */
    explicit CgroupController(const std::string &name, 
                              const std::string &parent_path)
        : name_(name), created_(false), auto_cleanup_(true) {
        cgroup_path_ = parent_path + "/" + name;
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
 * 
 * 使用 statfs 检测文件系统类型（nsjail 做法），比检查文件存在更健壮。
 */
inline bool is_cgroup_v2_available() {
    struct statfs buf;
    if (statfs("/sys/fs/cgroup", &buf) != 0) {
        return false;
    }
    // CGROUP2_SUPER_MAGIC = 0x63677270
    return buf.f_type == CGROUP2_SUPER_MAGIC;
}

/**
 * @brief cgroup 管理器
 * 
 * 负责管理 cgroup 层级结构，遵循 cgroup v2 "no internal processes" 规则。
 * 
 * 结构：
 *   <base_path>/           ← 被委派的 cgroup（来自 systemd-run）或容器根
 *   ├── judger/            ← main_judger 进程移动到这里
 *   └── sandbox/           ← 沙箱 cgroup 池的父目录
 *       ├── box_0/
 *       ├── box_1/
 *       └── ...
 */
class CgroupManager {
private:
    std::string base_path_;           ///< 基础 cgroup 路径（绝对路径）
    std::string sandbox_parent_;      ///< 沙箱 cgroup 的父路径
    bool initialized_;
    std::mutex mutex_;
    
    static constexpr const char* CGROUP_ROOT = "/sys/fs/cgroup";
    
    CgroupManager() : initialized_(false) {}
    
    /**
     * @brief 启用子 cgroup 的控制器
     */
    bool enable_controllers(const std::string& path) {
        std::ofstream subtree(path + "/cgroup.subtree_control");
        if (subtree) {
            subtree << "+memory +cpu +pids +io";
            return subtree.good();
        }
        return false;
    }
    
    /**
     * @brief 创建目录
     */
    bool create_dir(const std::string& path) {
        if (fs::exists(path)) return true;
        return mkdir(path.c_str(), 0755) == 0;
    }
    
    /**
     * @brief 移动进程到指定 cgroup
     */
    bool move_process(const std::string& cgroup_path, pid_t pid) {
        std::ofstream procs(cgroup_path + "/cgroup.procs");
        if (procs) {
            procs << pid;
            return procs.good();
        }
        return false;
    }

public:
    static CgroupManager& instance() {
        static CgroupManager mgr;
        return mgr;
    }
    
    /**
     * @brief 初始化 cgroup 管理器
     * 
     * 检测当前进程的 cgroup，设置正确的层级结构，
     * 并将当前进程移动到 judger/ 子 cgroup。
     * 
     * @return 是否初始化成功
     */
    Result<void> initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (initialized_) {
            return Ok();
        }
        
        // 1. 获取当前进程的 cgroup 路径
        std::string self_cgroup = get_self_cgroup_path();
        
        if (self_cgroup.empty() || self_cgroup == "/") {
            // 在根 cgroup 中（可能是 Docker 容器或无 systemd）
            base_path_ = CGROUP_ROOT;
        } else {
            // 在某个子 cgroup 中（可能是 systemd-run 创建的 scope）
            base_path_ = std::string(CGROUP_ROOT) + self_cgroup;
        }
        
        // 2. 验证 base_path 存在
        if (!fs::exists(base_path_)) {
            return Err<void>(ErrorCode::FILE_READ_ERROR,
                           "Base cgroup path does not exist: " + base_path_);
        }
        
        // ===== 遵循 cgroup v2 "no internal processes" 规则 =====
        // 必须先移动进程，然后才能启用 subtree_control
        // 否则会收到 EBUSY 错误
        
        // 3. 创建 judger/ 子 cgroup（不需要先启用控制器）
        std::string judger_path = base_path_ + "/judger";
        if (!create_dir(judger_path)) {
            return Err<void>(ErrorCode::FILE_WRITE_ERROR,
                           "Cannot create judger cgroup: " + judger_path);
        }
        
        // 4. 立即将当前进程移动到 judger/（腾出 base_path_）
        //    这是遵循 "no internal processes" 规则的关键步骤！
        if (!move_process(judger_path, getpid())) {
            return Err<void>(ErrorCode::FILE_WRITE_ERROR,
                           "Cannot move self to judger cgroup");
        }
        
        // 5. 现在 base_path_ 没有进程了，可以安全地启用控制器
        enable_controllers(base_path_);
        
        // 6. 创建 sandbox/ 子 cgroup（用于沙箱进程）
        sandbox_parent_ = base_path_ + "/sandbox";
        if (!create_dir(sandbox_parent_)) {
            return Err<void>(ErrorCode::FILE_WRITE_ERROR,
                           "Cannot create sandbox cgroup: " + sandbox_parent_);
        }
        
        // 7. 启用 sandbox 的子控制器
        enable_controllers(sandbox_parent_);
        
        initialized_ = true;
        return Ok();
    }
    
    /**
     * @brief 获取沙箱 cgroup 的父路径
     */
    const std::string& sandbox_parent_path() const {
        return sandbox_parent_;
    }
    
    /**
     * @brief 获取基础路径
     */
    const std::string& base_path() const {
        return base_path_;
    }
    
    /**
     * @brief 是否已初始化
     */
    bool is_initialized() const {
        return initialized_;
    }
};

/**
 * @brief cgroup 池 - 复用 cgroup 减少创建/销毁开销
 * 
 * 使用方法：
 *   // 先初始化管理器
 *   CgroupManager::instance().initialize();
 *   
 *   // 然后使用池
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
        
        // 确保 CgroupManager 已初始化
        auto& mgr = CgroupManager::instance();
        if (!mgr.is_initialized()) {
            auto result = mgr.initialize();
            if (!result.ok()) {
                return nullptr;
            }
        }
        
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
        
        // 创建新的（在 sandbox/ 下）
        std::string name = "box_" + std::to_string(getpid()) + "_" + std::to_string(next_id_++);
        auto cg = std::make_unique<CgroupController>(name, mgr.sandbox_parent_path());
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

/**
 * @brief 创建评测机专用 cgroup（便捷函数）
 */
inline Result<CgroupController> create_judge_cgroup(
    const std::string &name,
    uint64_t memory_mb,
    uint64_t max_pids = 1
) {
    // 确保管理器已初始化
    auto& mgr = CgroupManager::instance();
    if (!mgr.is_initialized()) {
        UOJ_TRY(mgr.initialize());
    }
    
    CgroupController cg(name, mgr.sandbox_parent_path());
    
    UOJ_TRY(cg.create());
    
    CgroupLimits limits;
    limits.set_memory(memory_mb)
          .disable_swap()
          .set_max_pids(max_pids);
    
    UOJ_TRY(cg.apply_limits(limits));
    
    return Ok(std::move(cg));
}

} // namespace sandbox
} // namespace uoj

#endif // UOJ_SANDBOX_CGROUP_H
