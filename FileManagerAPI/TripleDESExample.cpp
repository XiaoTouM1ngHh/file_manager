#include "TripleDESDecryptor.hpp"
#include <iostream>
#include <string>

#ifdef USE_NLOHMANN_JSON
#include <nlohmann/json.hpp>
#include <fstream>

// 手动解析JSON密钥文件（当没有nlohmann/json库时使用）
std::string extractKeyFromJsonFile(const std::string& jsonFilePath) {
    std::ifstream file(jsonFilePath);
    if (!file.is_open()) {
        throw std::runtime_error("无法打开JSON文件: " + jsonFilePath);
    }
    
    std::string line;
    std::string keyValue;
    
    while (std::getline(file, line)) {
        // 简单解析，查找 "key": "value" 模式
        size_t keyPos = line.find("\"key\"");
        if (keyPos != std::string::npos) {
            size_t colonPos = line.find(":", keyPos);
            if (colonPos != std::string::npos) {
                size_t valueStartPos = line.find("\"", colonPos);
                if (valueStartPos != std::string::npos) {
                    valueStartPos++; // 跳过第一个引号
                    size_t valueEndPos = line.find("\"", valueStartPos);
                    if (valueEndPos != std::string::npos) {
                        keyValue = line.substr(valueStartPos, valueEndPos - valueStartPos);
                        break;
                    }
                }
            }
        }
    }
    
    if (keyValue.empty()) {
        throw std::runtime_error("无法在JSON文件中找到key字段");
    }
    
    return keyValue;
}
#endif

int main(int argc, char* argv[]) {
    try {
        // 检查命令行参数
        if (argc < 4) {
            std::cout << "用法: " << argv[0] << " <密钥文件/Base64密钥> <加密文件> <输出文件>" << std::endl;
            std::cout << "注意: 加密文件需要是Base64编码的3DES加密文件" << std::endl;
            return 1;
        }

        std::string keyArg = argv[1];
        std::string encryptedFile = argv[2];
        std::string outputFile = argv[3];

        // 创建3DES解密器
        try {
            if (keyArg.find(".json") != std::string::npos) {
                std::cout << "从JSON文件加载密钥: " << keyArg << std::endl;
                
                // 两种方式加载密钥文件
                std::string keyValue;
                
#ifdef USE_NLOHMANN_JSON
                // 使用nlohmann/json库解析
                TripleDESDecryptor decryptor;
                if (!decryptor.loadKeyFromFile(keyArg)) {
                    std::cerr << "无法从JSON文件加载密钥" << std::endl;
                    return 1;
                }
                if (decryptBase64File(keyValue, encryptedFile, outputFile)) {
                    std::cout << "解密成功！输出文件: " << outputFile << std::endl;
                    return 0;
                }
#else
                // 手动解析JSON
                try {
                    keyValue = extractKeyFromJsonFile(keyArg);
                    if (decryptBase64File(keyValue, encryptedFile, outputFile)) {
                        std::cout << "解密成功！输出文件: " << outputFile << std::endl;
                        return 0;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "解析JSON文件失败: " << e.what() << std::endl;
                    return 1;
                }
#endif
            } else {
                // 直接使用Base64密钥
                std::cout << "使用提供的Base64密钥解密" << std::endl;
                if (decryptBase64File(keyArg, encryptedFile, outputFile)) {
                    std::cout << "解密成功！输出文件: " << outputFile << std::endl;
                    return 0;
                }
            }
            
            std::cerr << "解密失败!" << std::endl;
            return 1;
        } catch (const TripleDESException& e) {
            std::cerr << "3DES解密错误: " << e.what() << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
} 