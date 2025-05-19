# FileManagerAPI

FileManagerAPI是一个C++客户端库，用于与文件管理系统服务端API进行交互。该库提供了文件分类查询、文件信息获取、文件下载和MD5校验等功能。

## 功能特性

- 获取所有文件分类
- 获取指定分类下的文件列表
- 获取文件详细信息
- 下载文件内容
- 计算文件MD5值并进行校验
- 获取文件总数统计

## 依赖库

- Windows API (WinHTTP)
- nlohmann/json - JSON解析库
- 标准C++库 (filesystem, fstream等)

## 使用方法

### 初始化API客户端

```cpp
// 初始化API客户端
FileManagerAPI api(L"http://localhost:5000/api");
```

### 获取所有分类

```cpp
try {
    std::vector<CategoryInfo> categories = api.GetCategories();
    for (const auto& category : categories) {
        std::cout << "分类ID: " << category.id << std::endl;
        std::cout << "分类名称: " << category.name << std::endl;
        std::cout << "分类描述: " << category.description << std::endl;
    }
} catch (const FileManagerAPIException& e) {
    std::cerr << "错误: " << e.what() << std::endl;
}
```

### 获取分类下的文件

```cpp
try {
    int categoryId = 1; // 分类ID
    std::vector<FileInfo> files = api.GetFilesByCategory(categoryId);
    for (const auto& file : files) {
        std::cout << "文件GUID: " << file.guid << std::endl;
        std::cout << "文件名称: " << file.filename << std::endl;
        std::cout << "文件大小: " << file.size_formatted << std::endl;
    }
} catch (const FileManagerAPIException& e) {
    std::cerr << "错误: " << e.what() << std::endl;
}
```

### 下载文件

```cpp
try {
    std::string fileGuid = "file-guid-here";
    std::wstring savePath = L"C:\\Downloads\\myfile.txt";
    
    if (api.DownloadFile(fileGuid, savePath)) {
        std::cout << "文件下载成功" << std::endl;
        
        // 验证文件MD5
        FileInfo fileInfo = api.GetFileInfo(fileGuid);
        if (api.CompareFileMD5(fileInfo, savePath)) {
            std::cout << "MD5校验通过" << std::endl;
        } else {
            std::cout << "MD5校验失败" << std::endl;
        }
    } else {
        std::cout << "文件下载失败" << std::endl;
    }
} catch (const FileManagerAPIException& e) {
    std::cerr << "错误: " << e.what() << std::endl;
}
```

### 获取文件总数

```cpp
try {
    size_t totalFiles = api.GetTotalFiles();
    std::cout << "系统中的文件总数: " << totalFiles << std::endl;
} catch (const FileManagerAPIException& e) {
    std::cerr << "错误: " << e.what() << std::endl;
}
```

## 已知问题

### Unicode字符编码问题

目前API在处理返回的JSON中的中文字符时存在编码问题，特别是\uXXXX格式的Unicode编码。我们正在改进JSON解析和字符编码处理逻辑，以确保中文字符能够正确显示。


## 编译说明

该项目需要C++17或更高版本的编译器支持，并且依赖Windows平台API。确保在编译时链接以下库：

- winhttp.lib
- crypt32.lib

## 最近更新

- 改进了URL解析机制
- 添加了文件总数统计API
- 增强了错误处理和异常信息
- 优化了文件下载和MD5校验功能 