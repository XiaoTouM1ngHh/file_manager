# 文件管理系统

一个基于Flask和Bootstrap的文件管理系统，支持用户权限管理、加密存储和API接口。

## 功能特点

- **用户权限管理**：管理员和普通用户权限分离
- **文件加密存储**：支持使用密钥加密文件，保证文件安全
- **文件分类管理**：支持自定义文件分类
- **可定制上传规则**：可配置允许的文件类型
- **简洁现代的界面**：基于Bootstrap的响应式界面
- **完善的API接口**：支持第三方系统接入
- **C++客户端支持**：提供原生Windows C++客户端库

## 系统需求

- Python 3.8+
- 支持SQLite (默认), MySQL, PostgreSQL等数据库

## 安装步骤

1. 克隆仓库到本地
```bash
git clone https://github.com/yourusername/file-manager.git
cd file-manager
```

2. 创建并激活虚拟环境
```bash
# 使用 venv (Python内置)
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

3. 安装依赖
```bash
pip install -r requirements.txt
```

4. 启动应用
```bash
flask run
```

## 配置说明

系统配置主要通过以下方式进行：

1. 环境变量（推荐用于生产环境）
2. `.env` 文件（推荐用于开发环境）
3. `config.py` 文件中的默认配置

主要配置项:

- `SECRET_KEY`: 应用密钥，用于会话安全
- `DATABASE_URL`: 数据库连接URL
- `UPLOAD_FOLDER`: 文件上传目录
- `MAX_CONTENT_LENGTH`: 最大上传文件大小（字节）

## API文档

系统提供以下API接口：

### 获取所有分类
```
GET /api/categories
```

### 获取分类下所有文件
```
GET /api/categories/<category_id>/files
```

### 获取文件属性
```
GET /api/files/<file_guid>
```

### 获取文件内容
```
GET /api/files/<file_guid>/content
```

### 获取文件总数
```
GET /api/files/count
```

### 获取密钥信息
```
GET /api/keys
```

### 下载密钥
```
GET /api/keys/<key_id>/download
```

## C++客户端库

项目提供了Windows平台的C++客户端库（FileManagerAPI），用于与服务端API进行交互。

### 主要功能

- 获取所有文件分类
- 获取指定分类下的文件列表
- 获取文件详细信息
- 下载文件内容
- 计算文件MD5值并进行校验
- 获取文件总数统计

### 使用方法

请参考`FileManagerAPI/README.md`文件了解详细使用方法。

## 开发计划

- [x] 添加文件总数统计API
- [x] 添加密钥下载功能
- [x] 提供C++客户端库
- [ ] 添加HTTPS支持
- [ ] 支持批量上传/下载
- [ ] 增加文件预览功能
- [ ] 支持更多文件格式
- [ ] 增加文件分享功能
- [ ] 改进C++客户端的Unicode支持

## 许可证

本项目采用 MIT 许可证 


## 界面：
![](https://github.com/XiaoTouM1ngHh/file_manager/blob/main/admin.png)
![](https://github.com/XiaoTouM1ngHh/file_manager/blob/main/login.png)
