/**
 * @file config.h
 * @brief 配置系统
 * 
 * 管理题目配置和提交配置的读取与访问
 */

#ifndef UOJ_CORE_CONFIG_H
#define UOJ_CORE_CONFIG_H

#include <string>
#include <map>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include "core/types.h"

namespace uoj {

/**
 * @brief 配置管理类
 * 
 * 管理 key-value 格式的配置文件
 */
class Config {
private:
    std::map<std::string, std::string> data_;

public:
    Config() = default;
    
    /**
     * @brief 从文件加载配置
     * @param filename 配置文件路径
     * @return 是否成功加载
     */
    bool load(const std::string &filename) {
        std::ifstream fin(filename.c_str());
        if (!fin) {
            return false;
        }
        std::string key, val;
        while (fin >> key >> val) {
            data_[key] = val;
        }
        return true;
    }

    /**
     * @brief 设置配置项
     */
    void set(const std::string &key, const std::string &val) {
        data_[key] = val;
    }

    /**
     * @brief 添加配置项（如果不存在）
     */
    void add(const std::string &key, const std::string &val) {
        if (data_.count(key) == 0) {
            data_[key] = val;
        }
    }

    /**
     * @brief 检查配置项是否存在
     */
    bool has(const std::string &key) const {
        return data_.count(key) != 0;
    }

    /**
     * @brief 检查配置项是否等于指定值
     */
    bool is(const std::string &key, const std::string &val) const {
        auto it = data_.find(key);
        return it != data_.end() && it->second == val;
    }

    /**
     * @brief 获取字符串配置
     */
    std::string get_str(const std::string &key, const std::string &default_val = "") const {
        auto it = data_.find(key);
        return (it != data_.end()) ? it->second : default_val;
    }

    /**
     * @brief 获取带编号的字符串配置
     * @param key 基础键名
     * @param num 编号
     * @param default_val 默认值
     * @return 配置值，查找顺序: key_num -> default_val
     */
    std::string get_str(const std::string &key, int num, const std::string &default_val = "") const {
        std::ostringstream sout;
        sout << key << "_" << num;
        auto it = data_.find(sout.str());
        return (it != data_.end()) ? it->second : default_val;
    }

    /**
     * @brief 获取整数配置
     */
    int get_int(const std::string &key, int default_val = 0) const {
        auto it = data_.find(key);
        return (it != data_.end()) ? atoi(it->second.c_str()) : default_val;
    }

    /**
     * @brief 获取带编号的整数配置
     * @param key 基础键名
     * @param num 编号
     * @param default_val 默认值
     * @return 配置值，查找顺序: key_num -> key -> default_val
     */
    int get_int(const std::string &key, int num, int default_val) const {
        std::ostringstream sout;
        sout << key << "_" << num;
        auto it = data_.find(sout.str());
        if (it != data_.end()) {
            return atoi(it->second.c_str());
        }
        return get_int(key, default_val);
    }

    /**
     * @brief 获取运行限制配置
     * @param prefix 配置前缀
     * @param num 测试点编号
     * @param default_limit 默认限制
     */
    RunLimit get_run_limit(const std::string &prefix, int num, const RunLimit &default_limit) const {
        std::string pre = prefix.empty() ? "" : prefix + "_";
        RunLimit limit;
        limit.time = get_int(pre + "time_limit", num, default_limit.time);
        limit.memory = get_int(pre + "memory_limit", num, default_limit.memory);
        limit.output = get_int(pre + "output_limit", num, default_limit.output);
        limit.real_time = default_limit.real_time;
        return limit;
    }

    RunLimit get_run_limit(int num, const RunLimit &default_limit) const {
        return get_run_limit("", num, default_limit);
    }

    /**
     * @brief 获取输入文件名
     */
    std::string get_input_filename(int num) const {
        std::ostringstream name;
        if (num < 0) {
            name << "ex_";
        }
        name << get_str("input_pre", "input") << abs(num) << "." << get_str("input_suf", "txt");
        return name.str();
    }

    /**
     * @brief 获取输出文件名
     */
    std::string get_output_filename(int num) const {
        std::ostringstream name;
        if (num < 0) {
            name << "ex_";
        }
        name << get_str("output_pre", "output") << abs(num) << "." << get_str("output_suf", "txt");
        return name.str();
    }

    /**
     * @brief 打印所有配置（调试用）
     */
    void print() const {
        for (const auto &kv : data_) {
            fprintf(stderr, "%s = %s\n", kv.first.c_str(), kv.second.c_str());
        }
    }

    /**
     * @brief 获取内部 map（兼容旧代码）
     */
    std::map<std::string, std::string>& data() { return data_; }
    const std::map<std::string, std::string>& data() const { return data_; }
};

} // namespace uoj

#endif // UOJ_CORE_CONFIG_H

