import datetime
import uuid
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.ext.hybrid import hybrid_property

db = SQLAlchemy()

class User(db.Model, UserMixin):
    """用户模型"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(120), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # 关系
    files = db.relationship('File', backref='owner', lazy='dynamic')
    keys = db.relationship('EncryptionKey', backref='owner', lazy='dynamic')
    
    @property
    def password(self):
        """密码不可读取"""
        raise AttributeError('密码不可读取')
    
    @password.setter
    def password(self, password):
        """设置密码"""
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        """验证密码"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'


class FileCategory(db.Model):
    """文件分类模型"""
    __tablename__ = 'file_categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    description = db.Column(db.Text)
    color = db.Column(db.String(7))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    # 关系
    files = db.relationship('File', backref='category', lazy='dynamic')
    
    @hybrid_property
    def files_count(self):
        """返回该分类下的文件数量"""
        return self.files.count()
    
    def __repr__(self):
        return f'<FileCategory {self.name}>'


class File(db.Model):
    """文件模型"""
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    guid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    filename = db.Column(db.String(128))
    original_filename = db.Column(db.String(128))
    description = db.Column(db.Text)
    size = db.Column(db.Integer)  # 文件大小（字节）
    md5 = db.Column(db.String(32))  # 文件MD5哈希
    file_path = db.Column(db.String(255))  # 实际文件路径
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_key_id = db.Column(db.Integer, db.ForeignKey('encryption_keys.id'), nullable=True)
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('file_categories.id'))
    
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    def __repr__(self):
        return f'<File {self.filename}>'


class EncryptionKey(db.Model):
    """加密密钥模型"""
    __tablename__ = 'encryption_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    key_value = db.Column(db.Text)  # 加密后的密钥值
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # 关系
    files = db.relationship('File', backref='encryption_key', lazy='dynamic')
    
    def __repr__(self):
        return f'<EncryptionKey {self.name}>'


class AllowedExtension(db.Model):
    """允许的文件扩展名模型"""
    __tablename__ = 'allowed_extensions'
    
    id = db.Column(db.Integer, primary_key=True)
    extension = db.Column(db.String(16), unique=True)
    description = db.Column(db.String(128))
    icon = db.Column(db.String(64))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    @hybrid_property
    def files_count(self):
        """返回使用该扩展名的文件数量"""
        from sqlalchemy import func
        # 从File表中查询匹配此扩展名的文件数量
        return db.session.query(func.count(File.id)).filter(
            File.filename.like(f'%.{self.extension}')).scalar()
    
    def __repr__(self):
        return f'<AllowedExtension {self.extension}>' 