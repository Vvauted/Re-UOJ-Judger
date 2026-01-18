/**
 * @file languages/all.h
 * @brief 语言插件统一入口
 * 
 * 所有语言配置从 YAML 文件加载，不再硬编码
 */

#ifndef UOJ_LANGUAGES_ALL_H
#define UOJ_LANGUAGES_ALL_H

#include "core/language.h"
#include "core/language_loader.h"

namespace uoj {
namespace languages {

/**
 * @brief 初始化所有语言插件
 * 
 * 从指定目录加载所有 .yaml 配置文件
 * 
 * @param config_dir 配置目录路径，默认 "/opt/uoj_judger/config/languages"
 */
inline void init(const std::string& config_dir = "/opt/uoj_judger/config/languages") {
    load_languages_from_directory(config_dir);
}

/**
 * @brief 获取语言插件
 */
inline LanguagePlugin* get(const std::string& id) {
    return LanguageRegistry::instance().get(id);
}

/**
 * @brief 获取所有已注册的语言 ID
 */
inline std::vector<std::string> list() {
    return LanguageRegistry::instance().list();
}

/**
 * @brief 根据文件扩展名查找语言
 */
inline LanguagePlugin* find_by_extension(const std::string& ext) {
    for (const auto& id : list()) {
        auto lang = get(id);
        for (const auto& e : lang->file_extensions()) {
            if (e == ext) return lang;
        }
    }
    return nullptr;
}

/**
 * @brief 获取 YamlLanguagePlugin 指针（用于访问额外功能）
 */
inline YamlLanguagePlugin* as_yaml(LanguagePlugin* plugin) {
    return dynamic_cast<YamlLanguagePlugin*>(plugin);
}

} // namespace languages
} // namespace uoj

#endif // UOJ_LANGUAGES_ALL_H
