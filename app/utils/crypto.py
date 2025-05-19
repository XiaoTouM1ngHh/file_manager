import os
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import logging
import json
import time

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
            
        key_bytes = kdf.derive(password)
        
        # 使用标准Base64编码，更容易在C++中解码
        key_str = base64.b64encode(key_bytes).decode('utf-8')
        
        return key_str, base64.b64encode(salt).decode('utf-8')
    except Exception as e:
        logger.error(f"生成密钥失败: {str(e)}")
        raise


    """
    将密钥转换为C++友好的格式
    
    参数:
        key (str): 密钥字符串
        
    返回:
        str: C++可以直接使用的密钥
    """
    # 返回标准Base64编码的密钥
    if isinstance(key, str):
        key = key.encode('utf-8')
    # 确保是Base64格式
    try:
        # 如果已经是Base64字符串，解码后再重新编码保证格式一致
        key_bytes = base64.b64decode(key)
        return base64.b64encode(key_bytes).decode('utf-8')
    except:
        # 如果解码失败，尝试直接返回
        logger.warning("密钥格式转换失败，尝试直接返回")
        return key.decode('utf-8') if isinstance(key, bytes) else key

def encrypt_file(file_path, output_path, key):
    """
    加密文件 (AES-CBC)
    
    参数:
        file_path (str): 源文件路径
        output_path (str): 加密后的文件路径
        key (str): 加密密钥
        
    返回:
        str: 加密后的文件MD5哈希值
    """
    try:
        # 读取文件内容
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # 加密数据
        encrypted_data = encrypt_data_aes_cbc(data, key)
        
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

def encrypt_data_aes_cbc(data, key):
    """
    使用AES-CBC加密数据 - 适合C++解密
    格式：IV(16字节) + 加密数据
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # 解码Base64密钥
    key_bytes = base64.b64decode(key)
    # 截取前16字节用于AES-128
    key_bytes = key_bytes[:16]
    
    # 生成随机IV
    iv = os.urandom(16)
    
    # 添加PKCS7填充
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # 创建AES-CBC加密器
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 加密数据
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # 返回IV + 加密数据
    return iv + encrypted_data

def decrypt_file(file_path, output_path, key):
    """
    解密文件 (AES-CBC)
    
    参数:
        file_path (str): 加密文件路径
        output_path (str): 解密后的文件路径
        key (str): 解密密钥
        
    返回:
        bool: 解密是否成功
    """
    try:
        # 读取加密文件内容
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # 解密数据
        decrypted_data = decrypt_data_aes_cbc(encrypted_data, key)
        
        # 保存解密后的文件
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
            
        return True
    except Exception as e:
        logger.error(f"解密文件失败: {str(e)}")
        if os.path.exists(output_path):
            os.remove(output_path)  # 清理失败的文件
        return False

def decrypt_data_aes_cbc(encrypted_data, key):
    """
    使用AES-CBC解密数据 - 与C++兼容
    格式：IV(16字节) + 加密数据
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # 解码Base64密钥
    key_bytes = base64.b64decode(key)
    # 截取前16字节用于AES-128
    key_bytes = key_bytes[:16]
    
    # 提取IV（前16字节）
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # 创建AES-CBC解密器
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # 解密数据
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 移除PKCS7填充
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

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

    """
    创建密钥文件，包含解密需要的所有信息
    便于C++程序读取
    
    参数:
        key (str): 密钥
        salt (str): 盐值(Base64编码)
        output_path (str): 密钥文件保存路径
    """
    key_info = {
        "key": key,
        "salt": salt,
        "encryption_type": "aes-cbc",
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cpp_friendly": True
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(key_info, f, indent=2)
    
    logger.info(f"密钥文件已保存到: {output_path}")
    return output_path 