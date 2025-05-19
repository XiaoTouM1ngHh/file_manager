import os
import re
import logging
from werkzeug.utils import secure_filename

# 配置日志
logger = logging.getLogger(__name__)

def allowed_file(filename, allowed_extensions):
    """
    检查文件扩展名是否被允许
    
    参数:
        filename (str): 文件名
        allowed_extensions (set): 允许的扩展名集合
        
    返回:
        bool: 文件扩展名是否被允许
    """
    try:
        if '.' not in filename:
            return False
        ext = filename.rsplit('.', 1)[1].lower()
        return ext in allowed_extensions
    except Exception as e:
        logger.error(f"检查文件扩展名失败: {str(e)}")
        return False


def validate_email(email):
    """
    验证电子邮件格式
    
    参数:
        email (str): 电子邮件地址
        
    返回:
        bool: 电子邮件格式是否有效
    """
    try:
        pattern = r'^[\w.-]+@[a-zA-Z\d.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    except Exception as e:
        logger.error(f"验证电子邮件格式失败: {str(e)}")
        return False


def validate_username(username):
    """
    验证用户名格式
    
    参数:
        username (str): 用户名
        
    返回:
        bool: 用户名格式是否有效
    """
    try:
        # 用户名必须是3-20个字符，只能包含字母、数字、下划线或连字符
        pattern = r'^[a-zA-Z0-9_-]{3,20}$'
        return re.match(pattern, username) is not None
    except Exception as e:
        logger.error(f"验证用户名格式失败: {str(e)}")
        return False


def validate_password_strength(password):
    """
    验证密码强度
    
    参数:
        password (str): 密码
        
    返回:
        tuple: (bool, str) - 密码是否有效，以及错误消息(如果有)
    """
    try:
        # 密码长度检查
        if len(password) < 8:
            return False, "密码长度必须至少为8个字符"
        
        # 密码复杂度检查
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # 至少满足3个条件
        conditions_met = sum([has_upper, has_lower, has_digit, has_special])
        if conditions_met < 3:
            return False, "密码强度不足，需包含大写字母、小写字母、数字和特殊字符中的至少3种"
            
        return True, ""
    except Exception as e:
        logger.error(f"验证密码强度失败: {str(e)}")
        return False, f"验证密码时出错: {str(e)}"


def generate_safe_filename(filename, user_id=None):
    """
    生成安全的文件名
    
    参数:
        filename (str): 原始文件名
        user_id (int, optional): 用户ID，用于添加前缀
        
    返回:
        str: 安全的文件名
    """
    try:
        # 使用werkzeug的secure_filename转换为安全文件名
        safe_name = secure_filename(filename)
        
        # 如果提供了用户ID，添加前缀
        if user_id is not None:
            timestamp = int(os.path.getmtime(filename)) if os.path.exists(filename) else 0
            name, ext = os.path.splitext(safe_name)
            safe_name = f"user_{user_id}_{timestamp}_{name}{ext}"
            
        return safe_name
    except Exception as e:
        logger.error(f"生成安全文件名失败: {str(e)}")
        # 在出错时回退到基本的安全文件名
        return secure_filename(filename) 