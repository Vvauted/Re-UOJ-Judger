/**
 * @file logger.h
 * @brief 轻量级日志系统
 * 
 * 特性：
 * - 多日志级别 (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
 * - 支持控制台彩色输出
 * - 支持文件输出
 * - 格式化输出（时间戳、级别、位置）
 * - 线程安全
 * - 零依赖（仅标准库）
 */

#ifndef UOJ_CORE_LOGGER_H
#define UOJ_CORE_LOGGER_H

#include <string>
#include <fstream>
#include <iostream>
#include <sstream>
#include <ctime>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <memory>
#include <vector>
#include <cstdarg>

namespace uoj {

/**
 * @brief 日志级别
 */
enum class LogLevel {
    TRACE = 0,  ///< 最详细的跟踪信息
    DEBUG = 1,  ///< 调试信息
    INFO  = 2,  ///< 一般信息
    WARN  = 3,  ///< 警告
    ERROR = 4,  ///< 错误
    FATAL = 5,  ///< 致命错误
    OFF   = 6   ///< 关闭日志
};

/**
 * @brief 日志级别转字符串
 */
inline const char* level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "?????";
    }
}

/**
 * @brief 日志级别对应的 ANSI 颜色
 */
inline const char* level_to_color(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "\033[90m";      // 灰色
        case LogLevel::DEBUG: return "\033[36m";      // 青色
        case LogLevel::INFO:  return "\033[32m";      // 绿色
        case LogLevel::WARN:  return "\033[33m";      // 黄色
        case LogLevel::ERROR: return "\033[31m";      // 红色
        case LogLevel::FATAL: return "\033[35;1m";    // 粗体紫色
        default: return "";
    }
}

/**
 * @brief 日志输出接口
 */
class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void write(LogLevel level, const std::string &message) = 0;
    virtual void flush() = 0;
};

/**
 * @brief 控制台输出（支持彩色）
 */
class ConsoleSink : public LogSink {
private:
    bool use_color_;
    std::mutex mutex_;

public:
    explicit ConsoleSink(bool use_color = true) : use_color_(use_color) {}

    void write(LogLevel level, const std::string &message) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::ostream &out = (level >= LogLevel::WARN) ? std::cerr : std::cout;
        
        if (use_color_) {
            out << level_to_color(level) << message << "\033[0m" << std::endl;
        } else {
            out << message << std::endl;
        }
    }

    void flush() override {
        std::cout.flush();
        std::cerr.flush();
    }
};

/**
 * @brief 文件输出
 */
class FileSink : public LogSink {
private:
    std::ofstream file_;
    std::mutex mutex_;
    bool auto_flush_;

public:
    explicit FileSink(const std::string &filename, bool append = true, bool auto_flush = false)
        : auto_flush_(auto_flush) {
        file_.open(filename, append ? std::ios::app : std::ios::trunc);
    }

    ~FileSink() override {
        if (file_.is_open()) {
            file_.close();
        }
    }

    bool is_open() const { return file_.is_open(); }

    void write(LogLevel level, const std::string &message) override {
        if (!file_.is_open()) return;
        
        std::lock_guard<std::mutex> lock(mutex_);
        file_ << message << std::endl;
        if (auto_flush_) {
            file_.flush();
        }
    }

    void flush() override {
        if (file_.is_open()) {
            file_.flush();
        }
    }
};

/**
 * @brief 日志记录器
 */
class Logger {
private:
    std::string name_;
    LogLevel level_;
    std::vector<std::shared_ptr<LogSink>> sinks_;
    std::mutex mutex_;
    bool show_timestamp_;
    bool show_level_;
    bool show_location_;

    /**
     * @brief 获取当前时间戳字符串
     */
    static std::string get_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S")
            << '.' << std::setfill('0') << std::setw(3) << ms.count();
        return oss.str();
    }

    /**
     * @brief 提取文件名（不含路径）
     */
    static std::string basename(const std::string &path) {
        size_t pos = path.find_last_of("/\\");
        return (pos == std::string::npos) ? path : path.substr(pos + 1);
    }

public:
    explicit Logger(const std::string &name = "uoj")
        : name_(name), level_(LogLevel::INFO),
          show_timestamp_(true), show_level_(true), show_location_(false) {}

    // 配置方法
    Logger& set_level(LogLevel level) { level_ = level; return *this; }
    Logger& show_timestamp(bool show) { show_timestamp_ = show; return *this; }
    Logger& show_level(bool show) { show_level_ = show; return *this; }
    Logger& show_location(bool show) { show_location_ = show; return *this; }

    LogLevel level() const { return level_; }
    const std::string& name() const { return name_; }

    /**
     * @brief 添加输出目标
     */
    Logger& add_sink(std::shared_ptr<LogSink> sink) {
        sinks_.push_back(sink);
        return *this;
    }

    /**
     * @brief 添加控制台输出
     */
    Logger& add_console(bool use_color = true) {
        return add_sink(std::make_shared<ConsoleSink>(use_color));
    }

    /**
     * @brief 添加文件输出
     */
    Logger& add_file(const std::string &filename, bool append = true) {
        auto sink = std::make_shared<FileSink>(filename, append);
        if (sink->is_open()) {
            add_sink(sink);
        }
        return *this;
    }

    /**
     * @brief 清除所有输出目标
     */
    void clear_sinks() { sinks_.clear(); }

    /**
     * @brief 刷新所有输出
     */
    void flush() {
        for (auto &sink : sinks_) {
            sink->flush();
        }
    }

    /**
     * @brief 核心日志方法
     */
    void log(LogLevel level, const char *file, int line, const std::string &message) {
        if (level < level_) return;
        
        std::ostringstream oss;
        
        if (show_timestamp_) {
            oss << "[" << get_timestamp() << "] ";
        }
        
        if (show_level_) {
            oss << "[" << level_to_string(level) << "] ";
        }
        
        if (show_location_ && file) {
            oss << "[" << basename(file) << ":" << line << "] ";
        }
        
        oss << message;
        
        std::string formatted = oss.str();
        
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto &sink : sinks_) {
            sink->write(level, formatted);
        }
    }

    /**
     * @brief printf 风格日志
     */
    void logf(LogLevel level, const char *file, int line, const char *fmt, ...) {
        if (level < level_) return;
        
        char buffer[4096];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);
        
        log(level, file, line, buffer);
    }

    // 便捷方法
    void trace(const char *file, int line, const std::string &msg) { log(LogLevel::TRACE, file, line, msg); }
    void debug(const char *file, int line, const std::string &msg) { log(LogLevel::DEBUG, file, line, msg); }
    void info(const char *file, int line, const std::string &msg)  { log(LogLevel::INFO, file, line, msg); }
    void warn(const char *file, int line, const std::string &msg)  { log(LogLevel::WARN, file, line, msg); }
    void error(const char *file, int line, const std::string &msg) { log(LogLevel::ERROR, file, line, msg); }
    void fatal(const char *file, int line, const std::string &msg) { log(LogLevel::FATAL, file, line, msg); }
};

/**
 * @brief 全局默认日志器
 */
inline Logger& default_logger() {
    static Logger logger("uoj");
    static bool initialized = false;
    if (!initialized) {
        logger.add_console(true);
        initialized = true;
    }
    return logger;
}

/**
 * @brief 流式日志构建器
 */
class LogStream {
private:
    Logger &logger_;
    LogLevel level_;
    const char *file_;
    int line_;
    std::ostringstream stream_;

public:
    LogStream(Logger &logger, LogLevel level, const char *file, int line)
        : logger_(logger), level_(level), file_(file), line_(line) {}

    ~LogStream() {
        logger_.log(level_, file_, line_, stream_.str());
    }

    template<typename T>
    LogStream& operator<<(const T &value) {
        stream_ << value;
        return *this;
    }
};

} // namespace uoj

//==============================================================================
// 日志宏
//==============================================================================

/**
 * @brief 获取默认日志器
 */
#define LOG_DEFAULT() uoj::default_logger()

/**
 * @brief 设置日志级别
 */
#define LOG_SET_LEVEL(level) uoj::default_logger().set_level(level)

/**
 * @brief 流式日志宏
 */
#define LOG_TRACE uoj::LogStream(uoj::default_logger(), uoj::LogLevel::TRACE, __FILE__, __LINE__)
#define LOG_DEBUG uoj::LogStream(uoj::default_logger(), uoj::LogLevel::DEBUG, __FILE__, __LINE__)
#define LOG_INFO  uoj::LogStream(uoj::default_logger(), uoj::LogLevel::INFO,  __FILE__, __LINE__)
#define LOG_WARN  uoj::LogStream(uoj::default_logger(), uoj::LogLevel::WARN,  __FILE__, __LINE__)
#define LOG_ERROR uoj::LogStream(uoj::default_logger(), uoj::LogLevel::ERROR, __FILE__, __LINE__)
#define LOG_FATAL uoj::LogStream(uoj::default_logger(), uoj::LogLevel::FATAL, __FILE__, __LINE__)

/**
 * @brief printf 风格日志宏
 */
#define LOG_TRACEF(fmt, ...) uoj::default_logger().logf(uoj::LogLevel::TRACE, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_DEBUGF(fmt, ...) uoj::default_logger().logf(uoj::LogLevel::DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_INFOF(fmt, ...)  uoj::default_logger().logf(uoj::LogLevel::INFO,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARNF(fmt, ...)  uoj::default_logger().logf(uoj::LogLevel::WARN,  __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERRORF(fmt, ...) uoj::default_logger().logf(uoj::LogLevel::ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_FATALF(fmt, ...) uoj::default_logger().logf(uoj::LogLevel::FATAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @brief 条件日志
 */
#define LOG_IF(level, cond) if (cond) LOG_##level

/**
 * @brief 自定义日志器的日志宏
 */
#define LOGGER_TRACE(logger) uoj::LogStream(logger, uoj::LogLevel::TRACE, __FILE__, __LINE__)
#define LOGGER_DEBUG(logger) uoj::LogStream(logger, uoj::LogLevel::DEBUG, __FILE__, __LINE__)
#define LOGGER_INFO(logger)  uoj::LogStream(logger, uoj::LogLevel::INFO,  __FILE__, __LINE__)
#define LOGGER_WARN(logger)  uoj::LogStream(logger, uoj::LogLevel::WARN,  __FILE__, __LINE__)
#define LOGGER_ERROR(logger) uoj::LogStream(logger, uoj::LogLevel::ERROR, __FILE__, __LINE__)
#define LOGGER_FATAL(logger) uoj::LogStream(logger, uoj::LogLevel::FATAL, __FILE__, __LINE__)

#endif // UOJ_CORE_LOGGER_H

