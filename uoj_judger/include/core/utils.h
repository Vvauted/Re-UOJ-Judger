/**
 * @file utils.h
 * @brief 工具函数
 * 
 * 包含各种辅助函数：
 * - 命令执行
 * - 文件操作
 * - 字符串处理
 */

#ifndef UOJ_CORE_UTILS_H
#define UOJ_CORE_UTILS_H

#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <climits>
#include <locale>
#include <codecvt>
#include <algorithm>

namespace uoj {

//==============================================================================
// 命令执行
//==============================================================================

/**
 * @brief 转义 shell 参数
 * @param arg 原始参数
 * @return 转义后的参数（用单引号包裹）
 */
inline std::string escapeshellarg(const std::string &arg) {
    std::string res = "'";
    for (size_t i = 0; i < arg.size(); i++) {
        if (arg[i] == '\'') {
            res += "'\\''";
        } else {
            res += arg[i];
        }
    }
    res += "'";
    return res;
}

/**
 * @brief 获取真实路径
 * @param path 原始路径
 * @return 规范化的绝对路径，失败返回空字符串
 */
inline std::string get_realpath(const std::string &path) {
    char real[PATH_MAX + 1];
    if (realpath(path.c_str(), real) == NULL) {
        return "";
    }
    return real;
}

/**
 * @brief 执行 shell 命令
 * @param cmd 命令字符串
 * @return system() 的返回值
 */
inline int execute(const char *cmd) {
    return system(cmd);
}

inline int execute(const std::string &cmd) {
    return system(cmd.c_str());
}

/**
 * @brief 格式化执行 shell 命令
 * @param fmt printf 风格的格式字符串
 * @return system() 的返回值，格式化失败返回 -1
 */
inline int executef(const char *fmt, ...) {
    const int MaxL = 512;
    char cmd[MaxL];
    va_list ap;
    va_start(ap, fmt);
    int res = vsnprintf(cmd, MaxL, fmt, ap);
    if (res < 0 || res >= MaxL) {
        va_end(ap);
        return -1;
    }
    res = execute(cmd);
    va_end(ap);
    return res;
}

//==============================================================================
// 文件操作
//==============================================================================

/**
 * @brief 预览文件内容（支持 UTF-8）
 * @param name 文件路径
 * @param len 最大字符数
 * @return 文件内容预览，超长时添加 "..."
 */
inline std::string file_preview(const std::string &name, size_t len = 100) {
    std::wifstream f(name);
    if (!f) {
        return "";
    }
    f.imbue(std::locale("C.UTF-8"));

    std::vector<wchar_t> buf(len + 5, 0);
    f.read(&buf[0], len + 4);

    auto it = std::find(buf.begin(), buf.end(), 0);
    if (static_cast<size_t>(it - buf.begin()) > len + 3) {
        buf.resize(len);
        for (wchar_t c : L"...") {
            buf.push_back(c);
        }
    }
    
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> cv;
    return cv.to_bytes(&buf[0]);
}

/**
 * @brief 隐藏文件中的 token
 * @param name 文件路径
 * @param token 要隐藏的 token
 */
inline void file_hide_token(const std::string &name, const std::string &token) {
    executef("cp %s %s.bak", name.c_str(), name.c_str());

    FILE *rf = fopen((name + ".bak").c_str(), "r");
    FILE *wf = fopen(name.c_str(), "w");
    
    if (!rf || !wf) {
        if (rf) fclose(rf);
        if (wf) fclose(wf);
        return;
    }
    
    int c;
    for (size_t i = 0; i <= token.length(); i++) {
        c = fgetc(rf);
        if (c != (i < token.length() ? token[i] : '\n')) {
            fprintf(wf, "Unauthorized output\n");
            fclose(rf);
            fclose(wf);
            return;
        }
    }
    while ((c = fgetc(rf)) != EOF) {
        fputc(c, wf);
    }
    fclose(rf);
    fclose(wf);
}

/**
 * @brief 检查文件是否存在
 */
inline bool file_exists(const std::string &path) {
    FILE *f = fopen(path.c_str(), "r");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}

//==============================================================================
// 字符串处理
//==============================================================================

/**
 * @brief 任意类型转字符串
 */
template <class T>
inline std::string to_string(const T &v) {
    std::ostringstream sout;
    sout << v;
    return sout.str();
}

/**
 * @brief HTML 特殊字符转义
 */
inline std::string htmlspecialchars(const std::string &s) {
    std::string r;
    for (size_t i = 0; i < s.length(); i++) {
        switch (s[i]) {
            case '&':  r += "&amp;"; break;
            case '<':  r += "&lt;"; break;
            case '>':  r += "&gt;"; break;
            case '"':  r += "&quot;"; break;
            case '\0': r += "<b>\\0</b>"; break;
            default:   r += s[i]; break;
        }
    }
    return r;
}

/**
 * @brief 检查是否为非法关键字（asm）
 */
inline bool is_illegal_keyword(const std::string &name) {
    return (name == "__asm" || name == "__asm__" || name == "asm");
}

/**
 * @brief 检查文件中是否包含非法关键字
 */
inline bool has_illegal_keywords_in_file(const std::string &name) {
    FILE *f = fopen(name.c_str(), "r");
    if (!f) return false;

    int c;
    std::string key;
    while ((c = fgetc(f)) != EOF) {
        if (('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || 
            ('A' <= c && c <= 'Z') || c == '_') {
            if (key.size() < 20) {
                key += c;
            } else {
                if (is_illegal_keyword(key)) {
                    fclose(f);
                    return true;
                }
                key.erase(key.begin());
                key += c;
            }
        } else {
            if (is_illegal_keyword(key)) {
                fclose(f);
                return true;
            }
            key.clear();
        }
    }
    bool result = is_illegal_keyword(key);
    fclose(f);
    return result;
}

} // namespace uoj

#endif // UOJ_CORE_UTILS_H

