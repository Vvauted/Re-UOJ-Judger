/**
 * @file error.h
 * @brief 统一错误处理机制
 * 
 * 提供：
 * - Result<T, E> 类型：类似 Rust 的结果类型
 * - Error 基类和具体错误类型
 * - 错误码定义
 * - 错误传播宏
 */

#ifndef UOJ_CORE_ERROR_H
#define UOJ_CORE_ERROR_H

#include <string>
#include <variant>
#include <optional>
#include <stdexcept>
#include <sstream>
#include <ostream>

namespace uoj {

//==============================================================================
// 错误码定义
//==============================================================================

enum class ErrorCode {
    OK = 0,
    
    // 文件操作错误 (1xx)
    FILE_NOT_FOUND = 100,
    FILE_READ_ERROR = 101,
    FILE_WRITE_ERROR = 102,
    FILE_PERMISSION_DENIED = 103,
    
    // 配置错误 (2xx)
    CONFIG_PARSE_ERROR = 200,
    CONFIG_MISSING_KEY = 201,
    CONFIG_INVALID_VALUE = 202,
    
    // 编译错误 (3xx)
    COMPILE_ERROR = 300,
    COMPILE_TIMEOUT = 301,
    COMPILE_MEMORY_EXCEEDED = 302,
    COMPILER_NOT_FOUND = 303,
    UNSUPPORTED_LANGUAGE = 304,
    
    // 运行错误 (4xx)
    RUNTIME_ERROR = 400,
    TIME_LIMIT_EXCEEDED = 401,
    MEMORY_LIMIT_EXCEEDED = 402,
    OUTPUT_LIMIT_EXCEEDED = 403,
    DANGEROUS_SYSCALL = 404,
    SEGMENTATION_FAULT = 405,
    
    // 评测错误 (5xx)
    JUDGE_ERROR = 500,
    CHECKER_ERROR = 501,
    VALIDATOR_ERROR = 502,
    INTERACTOR_ERROR = 503,
    
    // 系统错误 (9xx)
    SYSTEM_ERROR = 900,
    FORK_FAILED = 901,
    EXEC_FAILED = 902,
    PIPE_FAILED = 903,
    UNKNOWN_ERROR = 999
};

/**
 * @brief 错误码转字符串
 */
inline const char* error_code_str(ErrorCode code);

/**
 * @brief 错误码输出流运算符
 */
inline std::ostream& operator<<(std::ostream &os, ErrorCode code) {
    return os << error_code_str(code);
}

inline const char* error_code_str(ErrorCode code) {
    switch (code) {
        case ErrorCode::OK: return "OK";
        case ErrorCode::FILE_NOT_FOUND: return "FILE_NOT_FOUND";
        case ErrorCode::FILE_READ_ERROR: return "FILE_READ_ERROR";
        case ErrorCode::FILE_WRITE_ERROR: return "FILE_WRITE_ERROR";
        case ErrorCode::FILE_PERMISSION_DENIED: return "FILE_PERMISSION_DENIED";
        case ErrorCode::CONFIG_PARSE_ERROR: return "CONFIG_PARSE_ERROR";
        case ErrorCode::CONFIG_MISSING_KEY: return "CONFIG_MISSING_KEY";
        case ErrorCode::CONFIG_INVALID_VALUE: return "CONFIG_INVALID_VALUE";
        case ErrorCode::COMPILE_ERROR: return "COMPILE_ERROR";
        case ErrorCode::COMPILE_TIMEOUT: return "COMPILE_TIMEOUT";
        case ErrorCode::COMPILE_MEMORY_EXCEEDED: return "COMPILE_MEMORY_EXCEEDED";
        case ErrorCode::COMPILER_NOT_FOUND: return "COMPILER_NOT_FOUND";
        case ErrorCode::UNSUPPORTED_LANGUAGE: return "UNSUPPORTED_LANGUAGE";
        case ErrorCode::RUNTIME_ERROR: return "RUNTIME_ERROR";
        case ErrorCode::TIME_LIMIT_EXCEEDED: return "TIME_LIMIT_EXCEEDED";
        case ErrorCode::MEMORY_LIMIT_EXCEEDED: return "MEMORY_LIMIT_EXCEEDED";
        case ErrorCode::OUTPUT_LIMIT_EXCEEDED: return "OUTPUT_LIMIT_EXCEEDED";
        case ErrorCode::DANGEROUS_SYSCALL: return "DANGEROUS_SYSCALL";
        case ErrorCode::SEGMENTATION_FAULT: return "SEGMENTATION_FAULT";
        case ErrorCode::JUDGE_ERROR: return "JUDGE_ERROR";
        case ErrorCode::CHECKER_ERROR: return "CHECKER_ERROR";
        case ErrorCode::VALIDATOR_ERROR: return "VALIDATOR_ERROR";
        case ErrorCode::INTERACTOR_ERROR: return "INTERACTOR_ERROR";
        case ErrorCode::SYSTEM_ERROR: return "SYSTEM_ERROR";
        case ErrorCode::FORK_FAILED: return "FORK_FAILED";
        case ErrorCode::EXEC_FAILED: return "EXEC_FAILED";
        case ErrorCode::PIPE_FAILED: return "PIPE_FAILED";
        default: return "UNKNOWN_ERROR";
    }
}

//==============================================================================
// Error 类
//==============================================================================

/**
 * @brief 错误信息类
 */
class Error {
private:
    ErrorCode code_;
    std::string message_;
    std::string file_;
    int line_;
    std::string context_;

public:
    Error() : code_(ErrorCode::OK), line_(0) {}
    
    Error(ErrorCode code, const std::string &message = "")
        : code_(code), message_(message), line_(0) {}
    
    Error(ErrorCode code, const std::string &message, 
          const char *file, int line)
        : code_(code), message_(message), file_(file ? file : ""), line_(line) {}

    // 链式设置
    Error& with_context(const std::string &ctx) {
        context_ = ctx;
        return *this;
    }

    // 访问器
    ErrorCode code() const { return code_; }
    const std::string& message() const { return message_; }
    const std::string& file() const { return file_; }
    int line() const { return line_; }
    const std::string& context() const { return context_; }
    
    bool ok() const { return code_ == ErrorCode::OK; }
    explicit operator bool() const { return !ok(); }  // true 表示有错误

    /**
     * @brief 格式化错误信息
     */
    std::string to_string() const {
        std::ostringstream oss;
        oss << "[" << error_code_str(code_) << "]";
        if (!message_.empty()) {
            oss << " " << message_;
        }
        if (!context_.empty()) {
            oss << " (context: " << context_ << ")";
        }
        if (!file_.empty() && line_ > 0) {
            oss << " at " << file_ << ":" << line_;
        }
        return oss.str();
    }
};

//==============================================================================
// Result<T> 类型
//==============================================================================

/**
 * @brief 结果类型，类似 Rust 的 Result<T, E>
 * 
 * 用法：
 *   Result<int> parse_int(const string &s);
 *   
 *   auto result = parse_int("42");
 *   if (result.ok()) {
 *       int value = result.value();
 *   } else {
 *       Error err = result.error();
 *   }
 */
template<typename T>
class Result {
private:
    std::variant<T, Error> data_;

public:
    // 成功构造
    Result(const T &value) : data_(value) {}
    Result(T &&value) : data_(std::move(value)) {}
    
    // 错误构造
    Result(const Error &err) : data_(err) {}
    Result(Error &&err) : data_(std::move(err)) {}
    Result(ErrorCode code, const std::string &msg = "") 
        : data_(Error(code, msg)) {}

    // 状态检查
    bool ok() const { return std::holds_alternative<T>(data_); }
    bool is_error() const { return std::holds_alternative<Error>(data_); }
    explicit operator bool() const { return ok(); }

    // 值访问
    T& value() & { return std::get<T>(data_); }
    const T& value() const & { return std::get<T>(data_); }
    T&& value() && { return std::get<T>(std::move(data_)); }
    
    // 带默认值的值访问
    T value_or(const T &default_val) const {
        return ok() ? std::get<T>(data_) : default_val;
    }

    // 错误访问
    Error& error() & { return std::get<Error>(data_); }
    const Error& error() const & { return std::get<Error>(data_); }

    // 解包（如果错误则抛异常）
    T& unwrap() & {
        if (is_error()) {
            throw std::runtime_error(error().to_string());
        }
        return value();
    }
    
    const T& unwrap() const & {
        if (is_error()) {
            throw std::runtime_error(error().to_string());
        }
        return value();
    }

    // map: 转换成功值
    template<typename Func>
    auto map(Func &&f) -> Result<decltype(f(std::declval<T>()))> {
        using U = decltype(f(std::declval<T>()));
        if (ok()) {
            return Result<U>(f(value()));
        }
        return Result<U>(error());
    }

    // and_then: 链式调用
    template<typename Func>
    auto and_then(Func &&f) -> decltype(f(std::declval<T>())) {
        if (ok()) {
            return f(value());
        }
        return decltype(f(std::declval<T>()))(error());
    }
};

/**
 * @brief 无值的结果类型（仅表示成功/失败）
 */
template<>
class Result<void> {
private:
    std::optional<Error> error_;

public:
    Result() : error_(std::nullopt) {}  // 成功
    Result(const Error &err) : error_(err) {}
    Result(Error &&err) : error_(std::move(err)) {}
    Result(ErrorCode code, const std::string &msg = "") 
        : error_(Error(code, msg)) {}

    bool ok() const { return !error_.has_value(); }
    bool is_error() const { return error_.has_value(); }
    explicit operator bool() const { return ok(); }

    Error& error() { return *error_; }
    const Error& error() const { return *error_; }
};

//==============================================================================
// 便捷函数
//==============================================================================

/**
 * @brief 创建成功结果
 */
template<typename T>
Result<T> Ok(T &&value) {
    return Result<T>(std::forward<T>(value));
}

inline Result<void> Ok() {
    return Result<void>();
}

/**
 * @brief 创建错误结果
 */
template<typename T = void>
Result<T> Err(ErrorCode code, const std::string &message = "") {
    return Result<T>(Error(code, message));
}

template<typename T = void>
Result<T> Err(const Error &err) {
    return Result<T>(err);
}

//==============================================================================
// 错误处理宏
//==============================================================================

/**
 * @brief 创建带位置信息的错误
 */
#define UOJ_ERROR(code, msg) \
    uoj::Error(code, msg, __FILE__, __LINE__)

/**
 * @brief 如果结果是错误，则返回错误（类似 Rust 的 ? 操作符）
 */
#define UOJ_TRY(expr) \
    do { \
        auto _result = (expr); \
        if (_result.is_error()) { \
            return _result.error(); \
        } \
    } while (0)

/**
 * @brief 如果结果是错误，则返回错误；否则解包值
 */
#define UOJ_TRY_UNWRAP(var, expr) \
    auto _tmp_##var = (expr); \
    if (_tmp_##var.is_error()) { \
        return _tmp_##var.error(); \
    } \
    auto var = std::move(_tmp_##var.value())

/**
 * @brief 断言条件，失败时返回错误
 */
#define UOJ_ENSURE(cond, code, msg) \
    do { \
        if (!(cond)) { \
            return UOJ_ERROR(code, msg); \
        } \
    } while (0)

/**
 * @brief 断言指针非空
 */
#define UOJ_ENSURE_NOT_NULL(ptr, msg) \
    UOJ_ENSURE((ptr) != nullptr, uoj::ErrorCode::SYSTEM_ERROR, msg)

} // namespace uoj

#endif // UOJ_CORE_ERROR_H

