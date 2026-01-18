/**
 * @file result.h
 * @brief 评测结果输出
 * 
 * 管理评测结果的收集和输出
 */

#ifndef UOJ_CORE_RESULT_H
#define UOJ_CORE_RESULT_H

#include <string>
#include <sstream>
#include <vector>
#include <cstdio>
#include <unistd.h>
#include <sys/file.h>
#include <cstdarg>
#include "core/types.h"
#include "core/utils.h"
#include "core/config.h"

namespace uoj {

/**
 * @brief 评测结果收集器
 * 
 * 收集各测试点的结果，并生成最终报告
 */
class JudgeResult {
private:
    int tot_time_ = 0;          ///< 总用时
    int max_memory_ = 0;        ///< 最大内存
    int tot_score_ = 0;         ///< 总分
    std::ostringstream details_; ///< 详细结果 XML

public:
    // Getters
    int total_time() const { return tot_time_; }
    int max_memory() const { return max_memory_; }
    int total_score() const { return tot_score_; }
    
    // Setters
    void set_total_score(int score) { tot_score_ = score; }
    void add_score(int score) { tot_score_ += score; }

    /**
     * @brief 添加测试点结果
     * @param info 测试点信息
     * @param config 配置（用于控制显示内容）
     * @param update_tot_score 是否更新总分
     */
    void add_point(const PointInfo &info, const Config &config, bool update_tot_score = true) {
        // 累计时间和内存
        if (info.num >= 0) {
            if (info.ust >= 0) {
                tot_time_ += info.ust;
            }
            if (info.usm >= 0) {
                max_memory_ = std::max(max_memory_, info.usm);
            }
        }
        if (update_tot_score) {
            tot_score_ += info.scr;
        }

        // 输出 XML
        details_ << "<test num=\"" << info.num << "\""
            << " score=\"" << info.scr << "\""
            << " info=\"" << htmlspecialchars(info.info) << "\""
            << " time=\"" << info.ust << "\""
            << " memory=\"" << info.usm << "\">" << std::endl;
        
        if (config.get_str("show_in", "on") == "on") {
            details_ << "<in>" << htmlspecialchars(info.in) << "</in>" << std::endl;
        }
        if (config.get_str("show_out", "on") == "on") {
            details_ << "<out>" << htmlspecialchars(info.out) << "</out>" << std::endl;
        }
        if (config.get_str("show_res", "on") == "on") {
            details_ << "<res>" << htmlspecialchars(info.res) << "</res>" << std::endl;
        }
        details_ << "</test>" << std::endl;
    }

    /**
     * @brief 添加自定义测试结果
     */
    void add_custom_test(const CustomTestInfo &info) {
        if (info.ust >= 0) {
            tot_time_ += info.ust;
        }
        if (info.usm >= 0) {
            max_memory_ = std::max(max_memory_, info.usm);
        }

        details_ << "<custom-test info=\"" << htmlspecialchars(info.info) << "\""
            << " time=\"" << info.ust << "\""
            << " memory=\"" << info.usm << "\">" << std::endl;
        if (!info.exp.empty()) {
            details_ << info.exp << std::endl;
        }
        details_ << "<out>" << htmlspecialchars(info.out) << "</out>" << std::endl;
        details_ << "</custom-test>" << std::endl;
    }

    /**
     * @brief 添加子任务结果
     */
    void add_subtask(int num, int scr, const std::string &info, 
                     const std::vector<PointInfo> &points, const Config &config) {
        details_ << "<subtask num=\"" << num << "\""
            << " score=\"" << scr << "\""
            << " info=\"" << htmlspecialchars(info) << "\">" << std::endl;
        
        tot_score_ += scr;
        
        for (const auto &point : points) {
            add_point(point, config, false);
        }
        
        details_ << "</subtask>" << std::endl;
    }

    /**
     * @brief 写入成功结果文件
     */
    void write_ok(const std::string &result_path) const {
        FILE *fres = fopen((result_path + "/result.txt").c_str(), "w");
        if (!fres) return;
        
        fprintf(fres, "score %d\n", tot_score_);
        fprintf(fres, "time %d\n", tot_time_);
        fprintf(fres, "memory %d\n", max_memory_);
        fprintf(fres, "details\n");
        fprintf(fres, "<tests>\n");
        fprintf(fres, "%s", details_.str().c_str());
        fprintf(fres, "</tests>\n");
        fclose(fres);
    }

    /**
     * @brief 写入评测失败结果
     */
    static void write_judgement_failed(const std::string &result_path, const std::string &info) {
        FILE *fres = fopen((result_path + "/result.txt").c_str(), "w");
        if (!fres) return;
        
        fprintf(fres, "error Judgement Failed\n");
        fprintf(fres, "details\n");
        fprintf(fres, "<error>%s</error>\n", htmlspecialchars(info).c_str());
        fclose(fres);
    }

    /**
     * @brief 写入编译错误结果
     */
    static void write_compile_error(const std::string &result_path, const RunCompilerResult &res) {
        FILE *fres = fopen((result_path + "/result.txt").c_str(), "w");
        if (!fres) return;
        
        fprintf(fres, "error Compile Error\n");
        fprintf(fres, "details\n");
        fprintf(fres, "<error>%s</error>\n", htmlspecialchars(res.info).c_str());
        fclose(fres);
    }
};

/**
 * @brief 报告评测状态
 * @param result_path 结果目录
 * @param status 状态字符串
 */
inline void report_status(const std::string &result_path, const char *status) {
    FILE *f = fopen((result_path + "/cur_status.txt").c_str(), "a");
    if (f == NULL) {
        return;
    }
    if (flock(fileno(f), LOCK_EX) != -1) {
        if (ftruncate(fileno(f), 0) != -1) {
            fprintf(f, "%s\n", status);
            fflush(f);
        }
        flock(fileno(f), LOCK_UN);
    }
    fclose(f);
}

/**
 * @brief 格式化报告评测状态
 */
inline bool report_status_f(const std::string &result_path, const char *fmt, ...) {
    const int MaxL = 512;
    char status[MaxL];
    va_list ap;
    va_start(ap, fmt);
    int res = vsnprintf(status, MaxL, fmt, ap);
    va_end(ap);
    
    if (res < 0 || res >= MaxL) {
        return false;
    }
    report_status(result_path, status);
    return true;
}

} // namespace uoj

#endif // UOJ_CORE_RESULT_H

