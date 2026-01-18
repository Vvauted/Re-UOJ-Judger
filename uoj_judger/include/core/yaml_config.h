/**
 * @file yaml_config.h
 * @brief 轻量级 YAML 配置解析器
 * 
 * 支持的 YAML 子集：
 * - 键值对
 * - 嵌套对象
 * - 列表（流式和块式）
 * - 注释
 * - 字符串（带引号和不带引号）
 */

#ifndef UOJ_CORE_YAML_CONFIG_H
#define UOJ_CORE_YAML_CONFIG_H

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <variant>
#include <memory>

namespace uoj {
namespace yaml {

//==============================================================================
// YAML 值类型
//==============================================================================

class YamlNode;
using YamlNodePtr = std::shared_ptr<YamlNode>;
using YamlMap = std::map<std::string, YamlNodePtr>;
using YamlList = std::vector<YamlNodePtr>;
using YamlValue = std::variant<std::monostate, std::string, int64_t, double, bool, YamlMap, YamlList>;

/**
 * @brief YAML 节点
 */
class YamlNode {
public:
    YamlValue value;
    
    YamlNode() : value(std::monostate{}) {}
    explicit YamlNode(const std::string& s) : value(s) {}
    explicit YamlNode(int64_t i) : value(i) {}
    explicit YamlNode(double d) : value(d) {}
    explicit YamlNode(bool b) : value(b) {}
    explicit YamlNode(const YamlMap& m) : value(m) {}
    explicit YamlNode(const YamlList& l) : value(l) {}
    
    bool is_null() const { return std::holds_alternative<std::monostate>(value); }
    bool is_string() const { return std::holds_alternative<std::string>(value); }
    bool is_int() const { return std::holds_alternative<int64_t>(value); }
    bool is_double() const { return std::holds_alternative<double>(value); }
    bool is_bool() const { return std::holds_alternative<bool>(value); }
    bool is_map() const { return std::holds_alternative<YamlMap>(value); }
    bool is_list() const { return std::holds_alternative<YamlList>(value); }
    
    std::string as_string(const std::string& def = "") const {
        if (is_string()) return std::get<std::string>(value);
        if (is_int()) return std::to_string(std::get<int64_t>(value));
        if (is_double()) return std::to_string(std::get<double>(value));
        if (is_bool()) return std::get<bool>(value) ? "true" : "false";
        return def;
    }
    
    int64_t as_int(int64_t def = 0) const {
        if (is_int()) return std::get<int64_t>(value);
        if (is_double()) return static_cast<int64_t>(std::get<double>(value));
        if (is_string()) {
            try { return std::stoll(std::get<std::string>(value)); }
            catch (...) { return def; }
        }
        return def;
    }
    
    double as_double(double def = 0.0) const {
        if (is_double()) return std::get<double>(value);
        if (is_int()) return static_cast<double>(std::get<int64_t>(value));
        if (is_string()) {
            try { return std::stod(std::get<std::string>(value)); }
            catch (...) { return def; }
        }
        return def;
    }
    
    bool as_bool(bool def = false) const {
        if (is_bool()) return std::get<bool>(value);
        if (is_string()) {
            auto s = std::get<std::string>(value);
            std::transform(s.begin(), s.end(), s.begin(), ::tolower);
            return s == "true" || s == "yes" || s == "1";
        }
        if (is_int()) return std::get<int64_t>(value) != 0;
        return def;
    }
    
    const YamlMap& as_map() const {
        static YamlMap empty;
        return is_map() ? std::get<YamlMap>(value) : empty;
    }
    
    const YamlList& as_list() const {
        static YamlList empty;
        return is_list() ? std::get<YamlList>(value) : empty;
    }
    
    // 获取子节点
    YamlNodePtr get(const std::string& key) const {
        if (!is_map()) return nullptr;
        auto& m = std::get<YamlMap>(value);
        auto it = m.find(key);
        return it != m.end() ? it->second : nullptr;
    }
    
    YamlNodePtr get(size_t index) const {
        if (!is_list()) return nullptr;
        auto& l = std::get<YamlList>(value);
        return index < l.size() ? l[index] : nullptr;
    }
    
    // 便捷访问（支持路径，如 "compiler.time_limit"）
    YamlNodePtr operator[](const std::string& path) const {
        size_t pos = path.find('.');
        if (pos == std::string::npos) {
            return get(path);
        }
        auto child = get(path.substr(0, pos));
        if (!child) return nullptr;
        return (*child)[path.substr(pos + 1)];
    }
    
    // 检查是否存在
    bool has(const std::string& key) const {
        return get(key) != nullptr;
    }
    
    // 获取字符串列表
    std::vector<std::string> as_string_list() const {
        std::vector<std::string> result;
        if (is_list()) {
            for (const auto& item : std::get<YamlList>(value)) {
                result.push_back(item->as_string());
            }
        }
        return result;
    }
    
    // 获取整数列表
    std::vector<int> as_int_list() const {
        std::vector<int> result;
        if (is_list()) {
            for (const auto& item : std::get<YamlList>(value)) {
                result.push_back(static_cast<int>(item->as_int()));
            }
        }
        return result;
    }
};

//==============================================================================
// YAML 解析器
//==============================================================================

class YamlParser {
private:
    std::vector<std::string> lines_;
    size_t current_line_ = 0;
    
    // 辅助函数
    static std::string trim(const std::string& s) {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }
    
    static size_t get_indent(const std::string& line) {
        size_t indent = 0;
        for (char c : line) {
            if (c == ' ') indent++;
            else if (c == '\t') indent += 2;
            else break;
        }
        return indent;
    }
    
    static std::string remove_comment(const std::string& line) {
        bool in_string = false;
        char quote_char = 0;
        for (size_t i = 0; i < line.size(); i++) {
            if (!in_string && (line[i] == '"' || line[i] == '\'')) {
                in_string = true;
                quote_char = line[i];
            } else if (in_string && line[i] == quote_char) {
                in_string = false;
            } else if (!in_string && line[i] == '#') {
                return line.substr(0, i);
            }
        }
        return line;
    }
    
    static std::string unquote(const std::string& s) {
        if (s.size() >= 2) {
            if ((s.front() == '"' && s.back() == '"') ||
                (s.front() == '\'' && s.back() == '\'')) {
                return s.substr(1, s.size() - 2);
            }
        }
        return s;
    }
    
    static YamlNodePtr parse_scalar(const std::string& s) {
        std::string value = trim(s);
        
        if (value.empty() || value == "~" || value == "null") {
            return std::make_shared<YamlNode>();
        }
        
        // 布尔值
        std::string lower = value;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower == "true" || lower == "yes") {
            return std::make_shared<YamlNode>(true);
        }
        if (lower == "false" || lower == "no") {
            return std::make_shared<YamlNode>(false);
        }
        
        // 带引号的字符串
        if ((value.front() == '"' && value.back() == '"') ||
            (value.front() == '\'' && value.back() == '\'')) {
            return std::make_shared<YamlNode>(unquote(value));
        }
        
        // 尝试解析为数字
        try {
            size_t pos;
            if (value.find('.') != std::string::npos) {
                double d = std::stod(value, &pos);
                if (pos == value.size()) {
                    return std::make_shared<YamlNode>(d);
                }
            } else {
                int64_t i = std::stoll(value, &pos);
                if (pos == value.size()) {
                    return std::make_shared<YamlNode>(i);
                }
            }
        } catch (...) {}
        
        // 默认为字符串
        return std::make_shared<YamlNode>(value);
    }
    
    // 解析流式列表 [a, b, c]
    static YamlNodePtr parse_flow_list(const std::string& s) {
        YamlList list;
        std::string content = trim(s.substr(1, s.size() - 2));
        
        if (content.empty()) {
            return std::make_shared<YamlNode>(list);
        }
        
        // 简单分割（不处理嵌套）
        std::stringstream ss(content);
        std::string item;
        while (std::getline(ss, item, ',')) {
            list.push_back(parse_scalar(trim(item)));
        }
        
        return std::make_shared<YamlNode>(list);
    }
    
    // 解析流式 map {a: 1, b: 2}
    static YamlNodePtr parse_flow_map(const std::string& s) {
        YamlMap map;
        std::string content = trim(s.substr(1, s.size() - 2));
        
        if (content.empty()) {
            return std::make_shared<YamlNode>(map);
        }
        
        std::stringstream ss(content);
        std::string pair;
        while (std::getline(ss, pair, ',')) {
            size_t colon = pair.find(':');
            if (colon != std::string::npos) {
                std::string key = trim(pair.substr(0, colon));
                std::string val = trim(pair.substr(colon + 1));
                map[unquote(key)] = parse_scalar(val);
            }
        }
        
        return std::make_shared<YamlNode>(map);
    }
    
    YamlNodePtr parse_block(size_t base_indent) {
        YamlMap map;
        YamlList list;
        bool is_list_mode = false;
        bool first = true;
        
        while (current_line_ < lines_.size()) {
            std::string line = remove_comment(lines_[current_line_]);
            std::string trimmed = trim(line);
            
            if (trimmed.empty()) {
                current_line_++;
                continue;
            }
            
            size_t indent = get_indent(line);
            
            if (indent < base_indent) {
                break;
            }
            
            if (indent > base_indent && !first) {
                break;
            }
            
            first = false;
            
            // 列表项
            if (trimmed[0] == '-') {
                is_list_mode = true;
                std::string item_content = trim(trimmed.substr(1));
                
                if (item_content.empty()) {
                    // 嵌套块
                    current_line_++;
                    list.push_back(parse_block(indent + 2));
                } else if (item_content.find(':') != std::string::npos) {
                    // 列表项是 map
                    current_line_++;
                    YamlMap item_map;
                    size_t colon = item_content.find(':');
                    std::string key = trim(item_content.substr(0, colon));
                    std::string val = trim(item_content.substr(colon + 1));
                    if (val.empty()) {
                        item_map[key] = parse_block(indent + 2);
                    } else {
                        item_map[key] = parse_value(val);
                    }
                    // 继续读取同级的键值对
                    while (current_line_ < lines_.size()) {
                        std::string next_line = remove_comment(lines_[current_line_]);
                        std::string next_trimmed = trim(next_line);
                        if (next_trimmed.empty()) {
                            current_line_++;
                            continue;
                        }
                        size_t next_indent = get_indent(next_line);
                        if (next_indent <= indent || next_trimmed[0] == '-') {
                            break;
                        }
                        size_t next_colon = next_trimmed.find(':');
                        if (next_colon != std::string::npos) {
                            std::string next_key = trim(next_trimmed.substr(0, next_colon));
                            std::string next_val = trim(next_trimmed.substr(next_colon + 1));
                            current_line_++;
                            if (next_val.empty()) {
                                item_map[next_key] = parse_block(next_indent + 2);
                            } else {
                                item_map[next_key] = parse_value(next_val);
                            }
                        } else {
                            break;
                        }
                    }
                    list.push_back(std::make_shared<YamlNode>(item_map));
                } else {
                    current_line_++;
                    list.push_back(parse_value(item_content));
                }
            }
            // 键值对
            else {
                size_t colon = trimmed.find(':');
                if (colon != std::string::npos) {
                    std::string key = trim(trimmed.substr(0, colon));
                    std::string val = trim(trimmed.substr(colon + 1));
                    current_line_++;
                    
                    if (val.empty()) {
                        map[key] = parse_block(indent + 2);
                    } else {
                        map[key] = parse_value(val);
                    }
                } else {
                    current_line_++;
                }
            }
        }
        
        if (is_list_mode) {
            return std::make_shared<YamlNode>(list);
        }
        return std::make_shared<YamlNode>(map);
    }
    
    YamlNodePtr parse_value(const std::string& s) {
        std::string value = trim(s);
        
        if (value.empty()) {
            return std::make_shared<YamlNode>();
        }
        
        // 流式列表
        if (value.front() == '[' && value.back() == ']') {
            return parse_flow_list(value);
        }
        
        // 流式 map
        if (value.front() == '{' && value.back() == '}') {
            return parse_flow_map(value);
        }
        
        return parse_scalar(value);
    }

public:
    YamlNodePtr parse(const std::string& content) {
        lines_.clear();
        current_line_ = 0;
        
        std::istringstream iss(content);
        std::string line;
        while (std::getline(iss, line)) {
            lines_.push_back(line);
        }
        
        return parse_block(0);
    }
    
    static YamlNodePtr load(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file: " + filename);
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        
        YamlParser parser;
        return parser.parse(buffer.str());
    }
};

//==============================================================================
// 便捷函数
//==============================================================================

inline YamlNodePtr load_yaml(const std::string& filename) {
    return YamlParser::load(filename);
}

inline YamlNodePtr parse_yaml(const std::string& content) {
    YamlParser parser;
    return parser.parse(content);
}

} // namespace yaml
} // namespace uoj

#endif // UOJ_CORE_YAML_CONFIG_H

