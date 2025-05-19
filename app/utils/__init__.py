import logging
import os
from logging.handlers import RotatingFileHandler
from flask import current_app

def setup_logging(app):
    """
    设置应用程序的日志系统
    
    参数:
        app: Flask应用实例
    """
    # 确保日志目录存在
    if not os.path.exists(app.config['LOG_DIR']):
        os.makedirs(app.config['LOG_DIR'])
    
    # 创建日志文件路径
    log_file = os.path.join(app.config['LOG_DIR'], 'file_manager.log')
    
    # 配置日志处理器
    file_handler = RotatingFileHandler(log_file, maxBytes=1024*1024*10, backupCount=5)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    
    # 配置应用日志
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('文件管理系统启动') 