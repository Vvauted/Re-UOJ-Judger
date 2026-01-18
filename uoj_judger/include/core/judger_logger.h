/**
 * @file judger_logger.h
 * @brief 评测机专用日志配置
 * 
 * 为评测机提供预配置的日志功能：
 * - 主日志（控制台 + 文件）
 * - 编译日志
 * - 运行日志
 * - 评测日志
 */

#ifndef UOJ_CORE_JUDGER_LOGGER_H
#define UOJ_CORE_JUDGER_LOGGER_H

#include "logger.h"
#include <string>

namespace uoj {

/**
 * @brief 评测机日志管理器
 */
class JudgerLogger {
private:
    Logger main_logger_;      ///< 主日志
    Logger compile_logger_;   ///< 编译日志
    Logger run_logger_;       ///< 运行日志
    Logger judge_logger_;     ///< 评测日志
    std::string log_dir_;

public:
    explicit JudgerLogger(const std::string &log_dir = "/tmp/uoj_judger/log")
        : main_logger_("main"),
          compile_logger_("compile"),
          run_logger_("run"),
          judge_logger_("judge"),
          log_dir_(log_dir) {}

    /**
     * @brief 初始化日志系统
     */
    void init(LogLevel level = LogLevel::INFO, bool console = true) {
        // 主日志
        main_logger_.set_level(level)
                    .show_timestamp(true)
                    .show_level(true)
                    .show_location(level <= LogLevel::DEBUG);
        
        if (console) {
            main_logger_.add_console(true);
        }
        main_logger_.add_file(log_dir_ + "/main.log");
        
        // 编译日志
        compile_logger_.set_level(level)
                       .show_timestamp(true)
                       .show_level(true)
                       .add_file(log_dir_ + "/compile.log");
        
        // 运行日志
        run_logger_.set_level(level)
                   .show_timestamp(true)
                   .show_level(true)
                   .add_file(log_dir_ + "/run.log");
        
        // 评测日志
        judge_logger_.set_level(level)
                     .show_timestamp(true)
                     .show_level(true)
                     .add_file(log_dir_ + "/judge.log");
    }

    /**
     * @brief 设置日志目录（需要在 init 之前调用）
     */
    void set_log_dir(const std::string &dir) {
        log_dir_ = dir;
    }

    // 获取各日志器
    Logger& main()    { return main_logger_; }
    Logger& compile() { return compile_logger_; }
    Logger& run()     { return run_logger_; }
    Logger& judge()   { return judge_logger_; }

    /**
     * @brief 刷新所有日志
     */
    void flush_all() {
        main_logger_.flush();
        compile_logger_.flush();
        run_logger_.flush();
        judge_logger_.flush();
    }

    /**
     * @brief 设置所有日志器级别
     */
    void set_all_levels(LogLevel level) {
        main_logger_.set_level(level);
        compile_logger_.set_level(level);
        run_logger_.set_level(level);
        judge_logger_.set_level(level);
    }
};

/**
 * @brief 获取全局评测机日志器
 */
inline JudgerLogger& judger_log() {
    static JudgerLogger instance;
    return instance;
}

} // namespace uoj

//==============================================================================
// 评测机专用日志宏
//==============================================================================

// 主日志
#define JLOG_TRACE LOGGER_TRACE(uoj::judger_log().main())
#define JLOG_DEBUG LOGGER_DEBUG(uoj::judger_log().main())
#define JLOG_INFO  LOGGER_INFO(uoj::judger_log().main())
#define JLOG_WARN  LOGGER_WARN(uoj::judger_log().main())
#define JLOG_ERROR LOGGER_ERROR(uoj::judger_log().main())
#define JLOG_FATAL LOGGER_FATAL(uoj::judger_log().main())

// 编译日志
#define CLOG_TRACE LOGGER_TRACE(uoj::judger_log().compile())
#define CLOG_DEBUG LOGGER_DEBUG(uoj::judger_log().compile())
#define CLOG_INFO  LOGGER_INFO(uoj::judger_log().compile())
#define CLOG_WARN  LOGGER_WARN(uoj::judger_log().compile())
#define CLOG_ERROR LOGGER_ERROR(uoj::judger_log().compile())

// 运行日志
#define RLOG_TRACE LOGGER_TRACE(uoj::judger_log().run())
#define RLOG_DEBUG LOGGER_DEBUG(uoj::judger_log().run())
#define RLOG_INFO  LOGGER_INFO(uoj::judger_log().run())
#define RLOG_WARN  LOGGER_WARN(uoj::judger_log().run())
#define RLOG_ERROR LOGGER_ERROR(uoj::judger_log().run())

// 评测日志
#define TLOG_TRACE LOGGER_TRACE(uoj::judger_log().judge())
#define TLOG_DEBUG LOGGER_DEBUG(uoj::judger_log().judge())
#define TLOG_INFO  LOGGER_INFO(uoj::judger_log().judge())
#define TLOG_WARN  LOGGER_WARN(uoj::judger_log().judge())
#define TLOG_ERROR LOGGER_ERROR(uoj::judger_log().judge())

// printf 风格
#define JLOG_INFOF(fmt, ...)  uoj::judger_log().main().logf(uoj::LogLevel::INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define JLOG_WARNF(fmt, ...)  uoj::judger_log().main().logf(uoj::LogLevel::WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define JLOG_ERRORF(fmt, ...) uoj::judger_log().main().logf(uoj::LogLevel::ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define CLOG_INFOF(fmt, ...)  uoj::judger_log().compile().logf(uoj::LogLevel::INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define RLOG_INFOF(fmt, ...)  uoj::judger_log().run().logf(uoj::LogLevel::INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define TLOG_INFOF(fmt, ...)  uoj::judger_log().judge().logf(uoj::LogLevel::INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#endif // UOJ_CORE_JUDGER_LOGGER_H

