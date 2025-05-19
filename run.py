import os
from app import create_app, db
from app.models import User, FileCategory, EncryptionKey, AllowedExtension, File

# 创建应用
app = create_app(os.getenv('FLASK_CONFIG') or 'default')


@app.shell_context_processor
def make_shell_context():
    """为Flask shell添加上下文"""
    return {
        'db': db,
        'User': User,
        'FileCategory': FileCategory,
        'EncryptionKey': EncryptionKey,
        'AllowedExtension': AllowedExtension,
        'File': File
    }


@app.cli.command('init-db')
def init_db():
    """初始化数据库"""
    db.create_all()
    print('数据库初始化完成')


@app.cli.command('create-admin')
def create_admin():
    """创建管理员账户"""
    username = input('请输入管理员用户名: ')
    email = input('请输入管理员邮箱: ')
    password = input('请输入管理员密码: ')
    
    user = User.query.filter_by(username=username).first()
    if user:
        print('用户已存在')
        return
    
    user = User(username=username, email=email, is_admin=True)
    user.password = password
    db.session.add(user)
    db.session.commit()
    print(f'管理员 {username} 创建成功')


@app.cli.command('init-extensions')
def init_extensions():
    """初始化默认允许的文件扩展名"""
    default_extensions = ['txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 
                         'jpg', 'jpeg', 'png', 'gif', 'zip', 'rar']
    
    for ext in default_extensions:
        if not AllowedExtension.query.filter_by(extension=ext).first():
            extension = AllowedExtension(extension=ext)
            db.session.add(extension)
    
    db.session.commit()
    print('默认文件扩展名初始化完成')


@app.cli.command('init-categories')
def init_categories():
    """初始化默认文件分类"""
    default_categories = [
        {'name': '文档', 'description': '文档、报告、合同等'},
        {'name': '图片', 'description': '照片、图表、设计图等'},
        {'name': '表格', 'description': 'Excel表格、数据文件等'},
        {'name': '演示文稿', 'description': 'PPT、幻灯片等'},
        {'name': '压缩包', 'description': 'ZIP、RAR等压缩文件'},
        {'name': '其他', 'description': '其他类型文件'}
    ]
    
    for cat in default_categories:
        if not FileCategory.query.filter_by(name=cat['name']).first():
            category = FileCategory(name=cat['name'], description=cat['description'])
            db.session.add(category)
    
    db.session.commit()
    print('默认文件分类初始化完成')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 