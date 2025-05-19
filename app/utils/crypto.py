import os
import base64
import hashlib
import logging
import json
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# 配置日志
logger = logging.getLogger(__name__)

def generate_key(password, salt=None):
    """
    生成3DES加密密钥 (24字节)
    
    参数:
        password (str): 用于生成密钥的密码
        salt (bytes, optional): 盐值，如果不提供则随机生成
        
    返回:
        tuple: (密钥字符串(Base64), 盐值(Base64))
    """
    try:
        if salt is None:
            salt = os.urandom(16)
        elif isinstance(salt, str):
            salt = salt.encode('utf-8')
            
        # 使用PBKDF2HMAC派生密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=24,  # 3DES需要24字节密钥
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        key_bytes = kdf.derive(password)
        
        # 使用标准Base64编码，便于C++解码
        key_str = base64.b64encode(key_bytes).decode('utf-8')
        
        return key_str, base64.b64encode(salt).decode('utf-8')
    except Exception as e:
        logger.error(f"生成密钥失败: {str(e)}")
        raise

def encrypt_file(file_path, output_path, key):
    """
    使用3DES-CBC加密文件，并进行Base64编码
    
    参数:
        file_path (str): 源文件路径
        output_path (str): 加密后的文件路径
        key (str): 加密密钥(Base64编码)
        
    返回:
        str: 加密后的文件MD5哈希值
    """
    try:
        # 读取文件内容
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # 加密数据
        encrypted_data = encrypt_data(data, key)
        
        # 对加密数据进行Base64编码
        base64_data = base64.b64encode(encrypted_data)
        
        # 保存加密并编码后的文件
        with open(output_path, 'wb') as f:
            f.write(base64_data)
        
        # 计算加密后文件的MD5哈希值
        md5_hash = hashlib.md5(encrypted_data).hexdigest()
        
        return md5_hash
    except Exception as e:
        logger.error(f"加密文件失败: {str(e)}")
        if os.path.exists(output_path):
            os.remove(output_path)  # 清理失败的文件
        raise

def encrypt_data(data, key):
    """
    使用3DES-CBC加密数据
    格式：IV(8字节) + 加密数据
    
    参数:
        data (bytes): 要加密的数据
        key (str): Base64编码的3DES密钥
        
    返回:
        bytes: IV + 加密后的数据
    """
    if isinstance(key, str):
        key = base64.b64decode(key)
    
    # 确保密钥是24字节(3DES)
    if len(key) != 24:
        raise ValueError("3DES密钥必须是24字节")
    
    # 生成随机IV (3DES使用8字节IV)
    iv = os.urandom(8)
    
    # 添加PKCS7填充
    padder = padding.PKCS7(64).padder()  # 3DES使用64位块
    padded_data = padder.update(data) + padder.finalize()
    
    # 创建3DES-CBC加密器
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 加密数据
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # 输出格式: IV + 加密数据
    return iv + encrypted_data

def decrypt_file(file_path, output_path, key):
    """
    使用3DES-CBC解密文件
    
    参数:
        file_path (str): 加密文件路径 (Base64编码)
        output_path (str): 解密后的文件路径
        key (str): 解密密钥(Base64编码)
        
    返回:
        bool: 解密是否成功
    """
    try:
        # 读取加密文件内容并进行Base64解码
        with open(file_path, 'rb') as f:
            base64_data = f.read()
        
        encrypted_data = base64.b64decode(base64_data)
        
        # 解密数据
        decrypted_data = decrypt_data(encrypted_data, key)
        
        # 保存解密后的文件
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
            
        return True
    except Exception as e:
        logger.error(f"解密文件失败: {str(e)}")
        if os.path.exists(output_path):
            os.remove(output_path)  # 清理失败的文件
        return False

def decrypt_data(encrypted_data, key):
    """
    使用3DES-CBC解密数据
    预期格式：IV(8字节) + 加密数据
    
    参数:
        encrypted_data (bytes): IV + 加密数据
        key (str): Base64编码的3DES密钥
        
    返回:
        bytes: 解密后的原始数据
    """
    if isinstance(key, str):
        key = base64.b64decode(key)
    
    # 确保密钥是24字节(3DES)
    if len(key) != 24:
        raise ValueError("3DES密钥必须是24字节")
    
    # 确保加密数据至少包含IV(8字节)
    if len(encrypted_data) <= 8:
        raise ValueError("加密数据长度不足，需要至少8字节的IV + 加密数据")
    
    # 提取IV和密文
    iv = encrypted_data[:8]
    ciphertext = encrypted_data[8:]
    
    # 创建3DES-CBC解密器
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # 解密数据
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 移除PKCS7填充
    unpadder = padding.PKCS7(64).unpadder()  # 3DES使用64位块
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

def create_key_file(key, salt, output_path):
    """
    创建密钥文件，便于C++程序读取
    
    参数:
        key (str): 密钥(Base64编码)
        salt (str): 盐值(Base64编码)
        output_path (str): 密钥文件保存路径
    """
    key_info = {
        "key": key,
        "salt": salt,
        "encryption": "3DES-CBC",
        "padding": "PKCS7",
        "format": "IV(8)+CIPHERTEXT",
        "encoding": "base64",
        "created": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(key_info, f, indent=2)
    
    logger.info(f"密钥文件已保存到: {output_path}")
    return output_path 