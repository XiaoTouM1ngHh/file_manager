import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import logging

# 配置日志
logger = logging.getLogger(__name__)

def generate_key(password, salt=None):
    """
    生成对称加密密钥
    
    参数:
        password (str): 用于生成密钥的密码
        salt (bytes, optional): 盐值，如果不提供则随机生成
        
    返回:
        tuple: (密钥字符串, 盐值)
    """
    try:
        if salt is None:
            salt = os.urandom(16)
        elif isinstance(salt, str):
            salt = salt.encode('utf-8')
            
        # 使用PBKDF2HMAC派生密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key.decode('utf-8'), base64.b64encode(salt).decode('utf-8')
    except Exception as e:
        logger.error(f"生成密钥失败: {str(e)}")
        raise


def encrypt_file(file_path, output_path, key):
    """
    加密文件
    
    参数:
        file_path (str): 源文件路径
        output_path (str): 加密后的文件路径
        key (str): 加密密钥
        
    返回:
        str: 加密后的文件MD5哈希值
    """
    try:
        if isinstance(key, str):
            key = key.encode('utf-8')
            
        cipher = Fernet(key)
        
        # 读取文件内容
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # 加密
        encrypted_data = cipher.encrypt(data)
        
        # 保存加密后的文件
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        # 计算加密后文件的MD5哈希值
        md5_hash = hashlib.md5(encrypted_data).hexdigest()
        
        return md5_hash
    except Exception as e:
        logger.error(f"加密文件失败: {str(e)}")
        if os.path.exists(output_path):
            os.remove(output_path)  # 清理失败的文件
        raise


def decrypt_file(file_path, output_path, key):
    """
    解密文件
    
    参数:
        file_path (str): 加密文件路径
        output_path (str): 解密后的文件路径
        key (str): 解密密钥
        
    返回:
        bool: 解密是否成功
    """
    try:
        if isinstance(key, str):
            key = key.encode('utf-8')
            
        cipher = Fernet(key)
        
        # 读取加密文件内容
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # 解密
        decrypted_data = cipher.decrypt(encrypted_data)
        
        # 保存解密后的文件
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
            
        return True
    except Exception as e:
        logger.error(f"解密文件失败: {str(e)}")
        if os.path.exists(output_path):
            os.remove(output_path)  # 清理失败的文件
        return False


def calculate_md5(file_path):
    """
    计算文件MD5哈希值
    
    参数:
        file_path (str): 文件路径
        
    返回:
        str: MD5哈希值
    """
    try:
        md5_hash = hashlib.md5()
        with open(file_path, 'rb') as f:
            # 读取文件块并更新哈希
            for chunk in iter(lambda: f.read(4096), b''):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    except Exception as e:
        logger.error(f"计算MD5失败: {str(e)}")
        raise 