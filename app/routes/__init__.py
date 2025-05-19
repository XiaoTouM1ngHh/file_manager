from flask import Blueprint

# 创建蓝图
auth_bp = Blueprint('auth', __name__)
admin_bp = Blueprint('admin', __name__)
file_bp = Blueprint('file', __name__)
api_bp = Blueprint('api', __name__, url_prefix='/api')

# 导入路由
from . import auth_routes, admin_routes, file_routes, api_routes

def register_blueprints(app):
    """
    注册所有蓝图到Flask应用
    
    参数:
        app: Flask应用实例
    """
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(file_bp)
    app.register_blueprint(api_bp) 