/**
 * @file types.h
 * @brief 核心数据结构定义
 * 
 * 包含评测机使用的所有基础数据结构：
 * - RunLimit: 资源限制
 * - RunResult: 运行结果
 * - PointInfo: 测试点信息
 * - 各种 Result 结构
 */

#ifndef UOJ_CORE_TYPES_H
#define UOJ_CORE_TYPES_H

#include <string>
#include <cstdio>
#include <cmath>
#include "uoj_env.h"

namespace uoj {

/**
 * @brief 资源限制配置
 */
struct RunLimit {
    int time;       ///< 时间限制（秒）
    int real_time;  ///< 实际时间限制（秒），-1 表示 time + 2
    int memory;     ///< 内存限制（MB）
    int output;     ///< 输出限制（MB）

    RunLimit() : time(1), memory(256), output(64), real_time(-1) {}
    
    RunLimit(int _time, int _memory, int _output)
        : time(_time), memory(_memory), output(_output), real_time(-1) {}
    
    RunLimit(int _time, int _memory, int _output, int _real_time)
        : time(_time), memory(_memory), output(_output), real_time(_real_time) {}
};

// 预定义资源限制常量
namespace limits {
    const RunLimit DEFAULT        = RunLimit(1, 256, 64);
    const RunLimit JUDGER         = RunLimit(600, 1024, 128);
    const RunLimit CHECKER        = RunLimit(5, 256, 64);
    const RunLimit INTERACTOR     = RunLimit(1, 256, 64);
    const RunLimit VALIDATOR      = RunLimit(5, 256, 64);
    const RunLimit MARKER         = RunLimit(5, 256, 64);
    const RunLimit COMPILER       = RunLimit(30, 4096, 128);
}

/**
 * @brief 运行结果
 */
struct RunResult {
    int type;       ///< 结果类型 (RS_AC, RS_TLE, RS_MLE, RS_RE, RS_DGS, RS_JGF)
    int ust;        ///< 用时（毫秒）
    int usm;        ///< 内存（KB）
    int exit_code;  ///< 退出码

    RunResult() : type(RS_JGF), ust(-1), usm(-1), exit_code(-1) {}
    
    RunResult(int _type, int _ust, int _usm, int _exit_code)
        : type(_type), ust(_ust), usm(_usm), exit_code(_exit_code) {}

    /**
     * @brief 创建失败结果
     */
    static RunResult failed_result() {
        RunResult res;
        res.type = RS_JGF;
        res.ust = -1;
        res.usm = -1;
        return res;
    }

    /**
     * @brief 从文件读取结果
     * @param file_name 结果文件路径
     * @return 解析后的运行结果
     */
    static RunResult from_file(const std::string &file_name) {
        RunResult res;
        FILE *fres = fopen(file_name.c_str(), "r");
        if (fres == NULL || 
            fscanf(fres, "%d %d %d %d", &res.type, &res.ust, &res.usm, &res.exit_code) != 4) {
            if (fres) fclose(fres);
            return RunResult::failed_result();
        }
        fclose(fres);
        return res;
    }
    
    bool is_accepted() const { return type == RS_AC; }
    bool is_failed() const { return type == RS_JGF; }
};

/**
 * @brief 测试点信息
 */
struct PointInfo {
    int num;            ///< 测试点编号
    int scr;            ///< 得分 (0-100)
    int ust;            ///< 用时（毫秒）
    int usm;            ///< 内存（KB）
    std::string info;   ///< 结果信息
    std::string in;     ///< 输入预览
    std::string out;    ///< 输出预览
    std::string res;    ///< checker 结果

    PointInfo() : num(0), scr(0), ust(-1), usm(-1) {}
    
    PointInfo(int _num, int _scr, int _ust, int _usm, 
              const std::string &_info,
              const std::string &_in, 
              const std::string &_out, 
              const std::string &_res)
        : num(_num), scr(_scr), ust(_ust), usm(_usm), 
          info(_info), in(_in), out(_out), res(_res) {
        // 自动设置默认 info
        if (info == "default") {
            if (scr == 0) {
                info = "Wrong Answer";
            } else if (scr == 100) {
                info = "Accepted";
            } else {
                info = "Acceptable Answer";
            }
        }
    }
};

/**
 * @brief 自定义测试信息
 */
struct CustomTestInfo {
    int ust;            ///< 用时
    int usm;            ///< 内存
    std::string info;   ///< 结果信息
    std::string exp;    ///< 额外信息
    std::string out;    ///< 输出预览

    CustomTestInfo() : ust(-1), usm(-1) {}
    
    CustomTestInfo(int _ust, int _usm, const std::string &_info,
                   const std::string &_exp, const std::string &_out)
        : ust(_ust), usm(_usm), info(_info), exp(_exp), out(_out) {}
};

/**
 * @brief Checker 运行结果
 */
struct RunCheckerResult {
    int type;           ///< 结果类型
    int ust;            ///< 用时
    int usm;            ///< 内存
    int scr;            ///< 得分 (0-100)
    std::string info;   ///< 结果信息

    RunCheckerResult() : type(RS_JGF), ust(-1), usm(-1), scr(0) {}

    static RunCheckerResult failed_result() {
        RunCheckerResult res;
        res.type = RS_JGF;
        res.ust = -1;
        res.usm = -1;
        res.scr = 0;
        res.info = "Checker Judgement Failed";
        return res;
    }

    /**
     * @brief 从文件和运行结果解析 checker 结果
     */
    static RunCheckerResult from_file(const std::string &file_name, const RunResult &rres);
};

/**
 * @brief Validator 运行结果
 */
struct RunValidatorResult {
    int type;
    int ust;
    int usm;
    bool succeeded;
    std::string info;

    RunValidatorResult() : type(RS_JGF), ust(-1), usm(-1), succeeded(false) {}

    static RunValidatorResult failed_result() {
        RunValidatorResult res;
        res.type = RS_JGF;
        res.ust = -1;
        res.usm = -1;
        res.succeeded = false;
        res.info = "Validator Judgement Failed";
        return res;
    }
};

/**
 * @brief 编译器运行结果
 */
struct RunCompilerResult {
    int type;
    int ust;
    int usm;
    bool succeeded;
    std::string info;

    RunCompilerResult() : type(RS_JGF), ust(-1), usm(-1), succeeded(false) {}

    static RunCompilerResult failed_result() {
        RunCompilerResult res;
        res.type = RS_JGF;
        res.ust = -1;
        res.usm = -1;
        res.succeeded = false;
        res.info = "Compile Failed";
        return res;
    }
};

/**
 * @brief 简单交互结果
 */
struct RunSimpleInteractionResult {
    RunResult res;              ///< 程序运行结果
    RunCheckerResult ires;      ///< 交互器结果
};

/**
 * @brief 获取结果类型的字符串描述
 */
inline std::string result_to_string(int type) {
    switch (type) {
        case RS_AC:  return "Accepted";
        case RS_WA:  return "Wrong Answer";
        case RS_RE:  return "Runtime Error";
        case RS_MLE: return "Memory Limit Exceeded";
        case RS_TLE: return "Time Limit Exceeded";
        case RS_OLE: return "Output Limit Exceeded";
        case RS_DGS: return "Dangerous Syscalls";
        case RS_JGF: return "Judgement Failed";
        default:     return "Unknown Result";
    }
}

inline std::string result_to_string(const RunResult &res) {
    return result_to_string(res.type);
}

} // namespace uoj

#endif // UOJ_CORE_TYPES_H

