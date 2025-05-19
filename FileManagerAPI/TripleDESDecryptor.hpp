#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include <memory>
#include <fstream>
#include <sstream>
#include <iostream>

// OpenSSL 头文件
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/des.h>

// JSON解析库 (可选，仅在加载密钥文件时使用)
#ifdef USE_NLOHMANN_JSON
#include <nlohmann/json.hpp>
#endif

/**
 * 3DES解密异常类
 */
class TripleDESException : public std::runtime_error {
public:
    explicit TripleDESException(const std::string& message)
        : std::runtime_error(message) {}
};

/**
 * 3DES解密器类
 * 
 * 实现与Python版crypto.py兼容的3DES-CBC解密功能
 * 支持Base64解码
 */
class TripleDESDecryptor {
public:
    /**
     * 构造函数
     */
    TripleDESDecryptor() : ctx(nullptr) {
        initOpenSSL();
        // 创建加密上下文
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw TripleDESException("无法创建OpenSSL加密上下文: " + getOpenSSLError());
        }
    }

    /**
     * 析构函数
     */
    ~TripleDESDecryptor() {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
            ctx = nullptr;
        }
    }

    /**
     * 禁用拷贝构造函数
     */
    TripleDESDecryptor(const TripleDESDecryptor&) = delete;
    TripleDESDecryptor& operator=(const TripleDESDecryptor&) = delete;
    TripleDESDecryptor(TripleDESDecryptor&&) = delete;
    TripleDESDecryptor& operator=(TripleDESDecryptor&&) = delete;

    /**
     * 设置解密密钥（Base64编码）
     * 
     * @param base64Key Base64编码的3DES密钥，需要是24字节长
     */
    void setKey(const std::string& base64Key) {
        try {
            // 解码Base64密钥
            key = base64Decode(base64Key);
            
            // 确保密钥长度正确 (3DES密钥长度为24字节)
            if (key.size() != 24) {
                throw TripleDESException("3DES密钥长度必须为24字节，当前长度: " + std::to_string(key.size()) + "字节");
            }
        }
        catch (const std::exception& e) {
            throw TripleDESException(std::string("设置密钥失败: ") + e.what());
        }
    }

#ifdef USE_NLOHMANN_JSON
    /**
     * 从密钥文件加载密钥
     * 
     * @param keyFilePath 密钥文件路径
     * @return 是否成功加载密钥
     */
    bool loadKeyFromFile(const std::string& keyFilePath) {
        try {
            // 打开并读取密钥文件
            std::ifstream keyFile(keyFilePath);
            if (!keyFile.is_open()) {
                throw TripleDESException("无法打开密钥文件: " + keyFilePath);
            }
            
            // 解析JSON
            nlohmann::json keyData;
            keyFile >> keyData;
            
            // 验证加密算法
            if (keyData.contains("encryption")) {
                std::string encryption = keyData["encryption"];
                if (encryption != "3DES-CBC") {
                    std::cerr << "警告: 密钥文件指定的加密算法不是3DES-CBC，而是: " << encryption << std::endl;
                }
            }
            
            // 获取密钥
            if (!keyData.contains("key") || !keyData["key"].is_string()) {
                throw TripleDESException("密钥文件格式错误: 缺少有效的'key'字段");
            }
            
            // 设置密钥
            setKey(keyData["key"]);
            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "加载密钥文件失败: " << e.what() << std::endl;
            return false;
        }
    }
#endif

    /**
     * 解密数据
     * 预期格式：IV(8字节) + 加密数据
     * 
     * @param encryptedData 加密数据
     * @return 解密后的原始数据
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encryptedData) {
        try {
            // 确保我们有密钥
            if (key.empty()) {
                throw TripleDESException("未设置解密密钥");
            }
            
            // 确保数据长度足够
            if (encryptedData.size() <= 8) {
                throw TripleDESException("加密数据太短，至少需要8字节的IV");
            }
            
            // 从加密数据中提取IV (前8个字节)
            std::vector<uint8_t> iv(encryptedData.begin(), encryptedData.begin() + 8);
            
            // 实际的加密数据 (跳过IV)
            std::vector<uint8_t> ciphertext(encryptedData.begin() + 8, encryptedData.end());
            
            // 初始化解密
            if (EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), nullptr, key.data(), iv.data()) != 1) {
                throw TripleDESException("初始化3DES解密失败: " + getOpenSSLError());
            }
            
            // 设置填充
            EVP_CIPHER_CTX_set_padding(ctx, 1); // 使用PKCS#7填充
            
            // 分配输出缓冲区（可能最大比输入长度大一个加密块）
            std::vector<uint8_t> decryptedData(ciphertext.size() + EVP_CIPHER_block_size(EVP_des_ede3_cbc()));
            int decryptedLen = 0;
            int finalLen = 0;
            
            // 执行解密
            if (EVP_DecryptUpdate(ctx, decryptedData.data(), &decryptedLen, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
                throw TripleDESException("3DES解密数据失败: " + getOpenSSLError());
            }
            
            // 处理最后的块和填充
            if (EVP_DecryptFinal_ex(ctx, decryptedData.data() + decryptedLen, &finalLen) != 1) {
                throw TripleDESException("3DES解密最终块失败: " + getOpenSSLError());
            }
            
            // 调整解密数据的大小为实际长度
            decryptedData.resize(decryptedLen + finalLen);
            return decryptedData;
        }
        catch (const std::exception& e) {
            throw TripleDESException(std::string("解密失败: ") + e.what());
        }
    }

    /**
     * 解密Base64编码的文件
     * 预期格式：Base64(IV(8字节) + 加密数据)
     * 
     * @param base64FilePath Base64编码的加密文件路径
     * @param outputFilePath 解密后的输出文件路径
     * @return 是否成功解密
     */
    bool decryptFile(const std::string& base64FilePath, const std::string& outputFilePath) {
        try {
            // 读取Base64编码的文件
            std::ifstream base64File(base64FilePath);
            if (!base64File.is_open()) {
                throw TripleDESException("无法打开Base64编码文件: " + base64FilePath);
            }
            
            // 读取所有Base64内容
            std::stringstream buffer;
            buffer << base64File.rdbuf();
            std::string base64Content = buffer.str();
            base64File.close();
            
            // Base64解码
            std::vector<uint8_t> encryptedData = base64Decode(base64Content);
            
            // 验证文件大小
            if (encryptedData.size() <= 8) {
                throw TripleDESException("加密数据太小，无法包含IV和加密数据");
            }
            
            // 解密数据
            std::vector<uint8_t> decryptedData = decrypt(encryptedData);
            
            // 写入解密后的文件
            std::ofstream outputFile(outputFilePath, std::ios::binary);
            if (!outputFile.is_open()) {
                throw TripleDESException("无法创建输出文件: " + outputFilePath);
            }
            
            outputFile.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
            outputFile.close();
            
            std::cout << "文件解密成功: " << outputFilePath << std::endl;
            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "文件解密失败: " << e.what() << std::endl;
            // 清理可能部分写入的输出文件
            std::remove(outputFilePath.c_str());
            return false;
        }
    }

    /**
     * 从Base64解码
     * 
     * @param base64String Base64编码的字符串
     * @return 解码后的二进制数据
     */
    static std::vector<uint8_t> base64Decode(const std::string& base64String) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        
        BIO* bmem = BIO_new_mem_buf(base64String.c_str(), static_cast<int>(base64String.length()));
        bmem = BIO_push(b64, bmem);
        
        std::vector<uint8_t> result(base64String.length()); // 足够大的缓冲区
        int decodedLength = BIO_read(bmem, result.data(), static_cast<int>(result.size()));
        
        BIO_free_all(bmem);
        
        if (decodedLength <= 0) {
            throw TripleDESException("Base64解码失败");
        }
        
        result.resize(decodedLength); // 调整为实际大小
        return result;
    }

private:
    // OpenSSL上下文
    EVP_CIPHER_CTX* ctx;

    // 解密密钥
    std::vector<uint8_t> key;
    
    /**
     * 初始化OpenSSL
     */
    void initOpenSSL() {
        // 初始化OpenSSL库
        static bool initialized = false;
        if (!initialized) {
            ERR_load_crypto_strings();
            OpenSSL_add_all_algorithms();
            initialized = true;
        }
    }
    
    /**
     * 获取OpenSSL错误信息
     * 
     * @return 错误信息字符串
     */
    static std::string getOpenSSLError() {
        char errBuf[256];
        unsigned long err = ERR_get_error();
        
        if (err == 0) {
            return "未知错误";
        }
        
        ERR_error_string_n(err, errBuf, sizeof(errBuf));
        return std::string(errBuf);
    }
};

/**
 * 简单的3DES解密帮助函数
 * 
 * @param base64Key Base64编码的3DES密钥
 * @param encryptedData 加密数据（IV + 密文）
 * @return 解密后的原始数据
 */
inline std::vector<uint8_t> decrypt3DES(const std::string& base64Key, const std::vector<uint8_t>& encryptedData) {
    TripleDESDecryptor decryptor;
    decryptor.setKey(base64Key);
    return decryptor.decrypt(encryptedData);
}

/**
 * 解密Base64编码的3DES加密数据
 * 
 * @param base64Key Base64编码的3DES密钥
 * @param base64Data Base64编码的加密数据
 * @return 解密后的原始数据
 */
inline std::vector<uint8_t> decryptBase64Data(const std::string& base64Key, const std::string& base64Data) {
    TripleDESDecryptor decryptor;
    decryptor.setKey(base64Key);
    return decryptor.decrypt(TripleDESDecryptor::base64Decode(base64Data));
}

/**
 * 解密Base64编码的文件
 * 
 * @param base64Key Base64编码的3DES密钥
 * @param base64FilePath Base64编码的加密文件路径
 * @param outputFilePath 解密后的输出文件路径
 * @return 是否成功解密
 */
inline bool decryptBase64File(const std::string& base64Key, const std::string& base64FilePath, const std::string& outputFilePath) {
    TripleDESDecryptor decryptor;
    decryptor.setKey(base64Key);
    return decryptor.decryptFile(base64FilePath, outputFilePath);
} 