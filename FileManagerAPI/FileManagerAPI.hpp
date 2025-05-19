#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <winhttp.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <wincrypt.h>
#include <sstream>
#include <iomanip>
#include <regex>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "Winhttp.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

// 自定义异常类
class FileManagerAPIException : public std::runtime_error {
public:
    explicit FileManagerAPIException(const std::string& message)
        : std::runtime_error(message) {}
    explicit FileManagerAPIException(const std::wstring& message)
        : std::runtime_error(std::string(message.begin(), message.end())) {}
};

// 文件信息结构
struct FileInfo {
    std::string guid;
    std::string filename;
    std::string description;
    std::string category_name;
    size_t size;
    std::string size_formatted;
    std::string md5;
    bool is_encrypted;
    std::string created_at;
    std::string updated_at;
    std::string extension;
};

// 分类信息结构
struct CategoryInfo {
    int id;
    std::string name;
    std::string description;
};

// API客户端类
class FileManagerAPI {
public:
    // 构造函数
    explicit FileManagerAPI(const std::wstring& baseUrl = L"http://localhost:5000/api") {
        // 手动解析URL
        parseUrl(baseUrl);
    }

    // 获取所有分类
    std::vector<CategoryInfo> GetCategories() {
        std::string response = MakeHttpRequest(L"categories", L"GET");
        if (response.empty()) {
            return {};
        }

        try {
            json result = json::parse(response);
            if (!result["success"].get<bool>()) {
                throw FileManagerAPIException(result["message"].get<std::string>());
            }

            std::vector<CategoryInfo> categories;
            for (const auto& category : result["data"]) {
                CategoryInfo info;
                info.id = category["id"].get<int>();
                info.name = category["name"].get<std::string>();
                info.description = category["description"].get<std::string>();
                categories.push_back(info);
            }
            return categories;
        }
        catch (const std::exception& e) {
            throw FileManagerAPIException(std::string("解析分类数据失败: ") + e.what());
        }
    }

    // 获取分类下的文件
    std::vector<FileInfo> GetFilesByCategory(int categoryId) {
        std::wstring endpoint = L"/categories/" + std::to_wstring(categoryId) + L"/files";
        std::string response = MakeHttpRequest(endpoint, L"GET");
        if (response.empty()) {
            return {};
        }

        try {
            json result = json::parse(response);
            if (!result["success"].get<bool>()) {
                throw FileManagerAPIException(result["message"].get<std::string>());
            }

            std::vector<FileInfo> files;
            for (const auto& file : result["data"]["files"]) {
                FileInfo info = GetFileInfo(file["guid"].get<std::string>());
                //info.guid = file["guid"].get<std::string>();
                //info.filename = file["filename"].get<std::string>();
                files.push_back(info);
            }
            return files;
        }
        catch (const std::exception& e) {
            throw FileManagerAPIException(std::string("解析文件数据失败: ") + e.what());
        }
    }

    // 获取文件详细信息
    FileInfo GetFileInfo(const std::string& fileGuid) {
        std::wstring endpoint = L"/files/" + std::wstring(fileGuid.begin(), fileGuid.end());
        std::string response = MakeHttpRequest(endpoint, L"GET");
        if (response.empty()) {
            throw FileManagerAPIException("获取文件信息失败");
        }

        try {
            json result = json::parse(response);
            if (!result["success"].get<bool>()) {
                throw FileManagerAPIException(result["message"].get<std::string>());
            }

            const auto& data = result["data"];
            FileInfo info;
            info.guid = data["guid"].get<std::string>();
            info.filename = data["filename"].get<std::string>();
            info.description = data["description"].get<std::string>();
            info.category_name = data["category"]["name"].get<std::string>();
            info.size = data["size"].get<size_t>();
            info.size_formatted = data["size_formatted"].get<std::string>();
            info.md5 = data["md5"].get<std::string>();
            info.is_encrypted = data["is_encrypted"].get<bool>();
            info.created_at = data["created_at"].get<std::string>();
            info.updated_at = data["updated_at"].get<std::string>();
            info.extension = data["extension"].get<std::string>();
            return info;
        }
        catch (const std::exception& e) {
            throw FileManagerAPIException(std::string("解析文件信息失败: ") + e.what());
        }
    }

    // 下载文件
    bool DownloadFile(const std::string& fileGuid, const std::string& savePath) {
        std::wstring endpoint = L"/files/" + std::wstring(fileGuid.begin(), fileGuid.end()) + L"/content";
        std::string response = MakeHttpRequest(endpoint, L"GET");
        if (response.empty()) {
            return false;
        }

        try {
            // 确保下载目录存在
            fs::path saveDir = fs::path(savePath).parent_path();
            if (!saveDir.empty()) {
                fs::create_directories(saveDir);
            }

            std::ofstream file(savePath, std::ios::binary);
            if (!file) {
                throw FileManagerAPIException("无法创建文件: " + savePath);
            }
            file.write(response.c_str(), response.length());
            return true;
        }
        catch (const std::exception& e) {
            throw FileManagerAPIException(std::string("保存文件失败: ") + e.what());
        }
    }

    // 下载文件2
    bool DownloadFile(const std::string& fileGuid, const std::wstring& savePath) {
        std::wstring endpoint = L"/files/" + std::wstring(fileGuid.begin(), fileGuid.end()) + L"/content";
        std::string response = MakeHttpRequest(endpoint, L"GET");
        if (response.empty()) {
            return false;
        }

        try {
            // 确保下载目录存在
            fs::path saveDir = fs::path(savePath).parent_path();
            if (!saveDir.empty()) {
                fs::create_directories(saveDir);
            }

            std::ofstream file(savePath, std::ios::binary);
            if (!file) {
                throw FileManagerAPIException(L"无法创建文件: " + savePath);
            }
            file.write(response.c_str(), response.length());
            return true;
        }
        catch (const std::exception& e) {
            throw FileManagerAPIException(std::string("保存文件失败: ") + e.what());
        }
    }
    

    // 计算本地文件的MD5值
    static std::string CalculateLocalFileMD5(const std::string& filePath) {
        try {
            // 打开文件
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                throw FileManagerAPIException("无法打开文件: " + filePath);
            }

            // 获取文件大小
            file.seekg(0, std::ios::end);
            size_t fileSize = file.tellg();
            file.seekg(0, std::ios::beg);

            // 创建MD5哈希对象
            HCRYPTPROV hProv = 0;
            HCRYPTHASH hHash = 0;
            BYTE hash[16];
            DWORD hashSize = sizeof(hash);

            if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                throw FileManagerAPIException("无法创建加密上下文");
            }

            if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
                CryptReleaseContext(hProv, 0);
                throw FileManagerAPIException("无法创建哈希对象");
            }

            // 读取文件并计算MD5
            const size_t bufferSize = 8192;
            std::vector<char> buffer(bufferSize);
            while (file) {
                file.read(buffer.data(), bufferSize);
                std::streamsize count = file.gcount();
                if (count > 0) {
                    if (!CryptHashData(hHash, (BYTE*)buffer.data(), count, 0)) {
                        CryptDestroyHash(hHash);
                        CryptReleaseContext(hProv, 0);
                        throw FileManagerAPIException("计算哈希值失败");
                    }
                }
            }

            // 获取最终的哈希值
            if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                throw FileManagerAPIException("获取哈希值失败");
            }

            // 清理资源
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);

            // 将哈希值转换为十六进制字符串
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (size_t i = 0; i < hashSize; ++i) {
                ss << std::setw(2) << static_cast<int>(hash[i]);
            }
            return ss.str();
        }
        catch (const std::exception& e) {
            throw FileManagerAPIException(std::string("计算文件MD5失败: ") + e.what());
        }
    }

    // 计算本地文件的MD5值
    static std::string CalculateLocalFileMD5(const std::wstring& filePath) {
        try {
            // 打开文件
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                throw FileManagerAPIException(L"无法打开文件: " + filePath);
            }

            // 获取文件大小
            file.seekg(0, std::ios::end);
            size_t fileSize = file.tellg();
            file.seekg(0, std::ios::beg);

            // 创建MD5哈希对象
            HCRYPTPROV hProv = 0;
            HCRYPTHASH hHash = 0;
            BYTE hash[16];
            DWORD hashSize = sizeof(hash);

            if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                throw FileManagerAPIException(L"无法创建加密上下文");
            }

            if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
                CryptReleaseContext(hProv, 0);
                throw FileManagerAPIException("无法创建哈希对象");
            }

            // 读取文件并计算MD5
            const size_t bufferSize = 8192;
            std::vector<char> buffer(bufferSize);
            while (file) {
                file.read(buffer.data(), bufferSize);
                std::streamsize count = file.gcount();
                if (count > 0) {
                    if (!CryptHashData(hHash, (BYTE*)buffer.data(), count, 0)) {
                        CryptDestroyHash(hHash);
                        CryptReleaseContext(hProv, 0);
                        throw FileManagerAPIException("计算哈希值失败");
                    }
                }
            }

            // 获取最终的哈希值
            if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                throw FileManagerAPIException("获取哈希值失败");
            }

            // 清理资源
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);

            // 将哈希值转换为十六进制字符串
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (size_t i = 0; i < hashSize; ++i) {
                ss << std::setw(2) << static_cast<int>(hash[i]);
            }
            return ss.str();
        }
        catch (const std::exception& e) {
            throw FileManagerAPIException(std::string("计算文件MD5失败: ") + e.what());
        }
    }


    // 比较文件MD5
    bool CompareFileMD5(const std::string& fileGuid, const std::string& localFilePath) {
        try {
            FileInfo fileInfo = GetFileInfo(fileGuid);
            std::string localMD5 = CalculateLocalFileMD5(localFilePath);
            return fileInfo.md5 == localMD5;
        }
        catch (const std::exception& e) {
            throw FileManagerAPIException(std::string("比较文件MD5失败: ") + e.what());
        }
    }
    // 比较文件MD5
    bool CompareFileMD5(const FileInfo& fileInfo, const std::wstring& localFilePath) {
        try {
            //FileInfo fileInfo = GetFileInfo(fileGuid);
            std::string localMD5 = CalculateLocalFileMD5(localFilePath);
            return fileInfo.md5 == localMD5;
        }
        catch (const std::exception& e) {
            throw FileManagerAPIException(std::string("比较文件MD5失败: ") + e.what());
        }
    }

    // 获取文件总数
    size_t GetTotalFiles() {
        std::string response = MakeHttpRequest(L"/files/count", L"GET");
        if (response.empty()) {
            throw FileManagerAPIException("获取文件总数失败");
        }

        try {
            json result = json::parse(response);
            if (!result["success"].get<bool>()) {
                throw FileManagerAPIException(result["message"].get<std::string>());
            }

            return result["data"]["total"].get<size_t>();
        }
        catch (const std::exception& e) {
            throw FileManagerAPIException(std::string("解析文件总数失败: ") + e.what());
        }
    }

private:
    std::wstring hostName_;    // 主机名
    INTERNET_PORT port_;       // 端口号
    std::wstring urlPath_;     // URL路径前缀
    bool isSecure_;            // 是否是HTTPS



    // 解析URL
    void parseUrl(const std::wstring& url) {
        try {
            // 默认值
            hostName_ = L"localhost";
            port_ = 80;
            urlPath_ = L"/";
            isSecure_ = false;

            // 匹配URL模式
            std::wregex urlRegex(L"(http|https)://([^:/]+)(?::(\\d+))?(/.*)?");
            std::wsmatch matches;
            if (std::regex_match(url, matches, urlRegex)) {
                // 协议
                std::wstring protocol = matches[1].str();
                isSecure_ = (protocol == L"https");

                // 主机名
                hostName_ = matches[2].str();

                // 端口
                if (matches[3].matched) {
                    port_ = static_cast<INTERNET_PORT>(std::stoi(matches[3].str()));
                }
                else {
                    port_ = isSecure_ ? 443 : 80;
                }

                // 路径
                if (matches[4].matched) {
                    urlPath_ = matches[4].str();
                }

                // 确保路径以/结尾
                if (urlPath_.empty() || urlPath_.back() != L'/') {
                    urlPath_ += L'/';
                }
            }
            else {
                throw FileManagerAPIException("无效的URL格式");
            }
        }
        catch (const std::exception& e) {
            throw FileManagerAPIException(std::string("解析URL失败: ") + e.what());
        }
    }

    // HTTP请求辅助函数
    std::string MakeHttpRequest(const std::wstring& endpoint, const std::wstring& method, const std::string& data = "") {
        // 创建会话
        std::unique_ptr<void, decltype(&WinHttpCloseHandle)> hSession(
            WinHttpOpen(L"FileManagerAPI/1.0",
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS,
                0),
            WinHttpCloseHandle
        );

        if (!hSession) {
            throw FileManagerAPIException("无法创建HTTP会话");
        }

        // 创建连接
        std::unique_ptr<void, decltype(&WinHttpCloseHandle)> hConnect(
            WinHttpConnect(hSession.get(),
                hostName_.c_str(),
                port_,
                0),
            WinHttpCloseHandle
        );

        if (!hConnect) {
            throw FileManagerAPIException("无法连接到服务器");
        }

        // 构建完整的URL路径
        std::wstring fullPath = urlPath_;
        // 如果endpoint以/开头并且urlPath_以/结尾，则去掉endpoint开头的/
        if (!endpoint.empty() && endpoint[0] == L'/' && !urlPath_.empty() && urlPath_.back() == L'/') {
            fullPath += endpoint.substr(1);
        }
        else {
            fullPath += endpoint;
        }

        // 创建请求
        std::unique_ptr<void, decltype(&WinHttpCloseHandle)> hRequest(
            WinHttpOpenRequest(hConnect.get(),
                method.c_str(),
                fullPath.c_str(),
                NULL,
                WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES,
                isSecure_ ? WINHTTP_FLAG_SECURE : 0),
            WinHttpCloseHandle
        );

        if (!hRequest) {
            throw FileManagerAPIException("无法创建HTTP请求");
        }

        // 设置请求头
        std::wstring headers = L"Content-Type: application/json\r\nAccept-Charset: UTF-8\r\n";
        if (!WinHttpAddRequestHeaders(hRequest.get(),
            headers.c_str(),
            (DWORD)headers.length(),
            WINHTTP_ADDREQ_FLAG_ADD)) {
            throw FileManagerAPIException("无法添加请求头");
        }

        // 发送请求
        bool result = false;
        if (data.empty()) {
            result = WinHttpSendRequest(hRequest.get(),
                WINHTTP_NO_ADDITIONAL_HEADERS,
                0,
                WINHTTP_NO_REQUEST_DATA,
                0,
                0,
                0);
        }
        else {
            result = WinHttpSendRequest(hRequest.get(),
                WINHTTP_NO_ADDITIONAL_HEADERS,
                0,
                (LPVOID)data.c_str(),
                (DWORD)data.length(),
                (DWORD)data.length(),
                0);
        }

        if (!result) {
            throw FileManagerAPIException("发送请求失败");
        }

        // 接收响应
        if (!WinHttpReceiveResponse(hRequest.get(), NULL)) {
            throw FileManagerAPIException("接收响应失败");
        }

        // 读取响应数据
        std::string response;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        char* pszOutBuffer;
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest.get(), &dwSize)) {
                break;
            }

            pszOutBuffer = new char[dwSize + 1];
            if (!pszOutBuffer) {
                dwSize = 0;
                break;
            }

            ZeroMemory(pszOutBuffer, dwSize + 1);

            if (!WinHttpReadData(hRequest.get(), (LPVOID)pszOutBuffer,
                dwSize, &dwDownloaded)) {
                delete[] pszOutBuffer;
                break;
            }

            response.append(pszOutBuffer, dwDownloaded);
            delete[] pszOutBuffer;

        } while (dwSize > 0);

        return response;
    }
};