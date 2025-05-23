import os
from flask import Flask, render_template, redirect, url_for, flash, g, request
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from app.models import db, User
from app.utils import setup_logging
from app.routes import register_blueprints
from config import config

# 初始化扩展
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = '请先登录再访问此页面'
login_manager.login_message_category = 'info'

# 标记是否已完成首次请求检查
_first_request_processed = False


@login_manager.user_loader
def load_user(user_id):
    """加载用户"""
    return User.query.get(int(user_id))


def create_app(config_name='default'):
    """创建Flask应用"""
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # 初始化扩展
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    migrate = Migrate(app, db)
    
    # 设置日志
    setup_logging(app)
    
    # 注册蓝图
    register_blueprints(app)
    
    # 确保上传目录存在
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # 确保日志目录存在
    if not os.path.exists(app.config['LOG_DIR']):
        os.makedirs(app.config['LOG_DIR'])
    
    # 注册错误处理
    register_error_handlers(app)
    
    # 注册启动检查函数
    register_startup_checks(app)
    
    # 在应用启动时立即检查数据库
    with app.app_context():
        check_database(app)
    
    return app


def register_error_handlers(app):
    """注册错误处理"""
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('errors/500.html'), 500
    
    # 处理favicon.ico请求
    @app.route('/favicon.ico')
    def favicon():
        from flask import send_from_directory
        return send_from_directory(os.path.join(app.root_path, 'static'),
                                  'favicon.ico', mimetype='image/vnd.microsoft.icon')


def register_startup_checks(app):
    """注册应用启动时的检查函数"""
    
    @app.before_request
    def check_setup():
        """检查应用是否已正确设置"""
        global _first_request_processed
        
        # 避免每次请求都执行检查
        if _first_request_processed:
            return
            
        _first_request_processed = True
        
        # 检查是否存在管理员账户
        if not check_admin_exists():
            # 如果当前访问的已经是setup页面，不再重定向
            if request.endpoint != 'admin.setup':
                flash('系统尚未创建管理员账户，请先创建一个管理员账户', 'warning')
                return redirect(url_for('admin.setup'))


def check_database(app):
    """检查数据库是否存在，不存在则创建"""
    db_path = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    
    # 如果是SQLite数据库
    if db_path.startswith('sqlite:///'):
        # 移除sqlite:///前缀获取文件路径
        db_file = db_path.replace('sqlite:///', '')
        
        # 确保目录存在
        db_dir = os.path.dirname(db_file)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
            app.logger.info(f"创建数据库目录: {db_dir}")
        
        # 检查数据库文件
        if os.path.exists(db_file):
            app.logger.info(f"数据库文件 {db_file} 已存在")
        else:
            app.logger.info(f"数据库文件 {db_file} 不存在，正在创建...")
            db.create_all()
            app.logger.info("数据库表创建完成")


def check_admin_exists():
    """检查是否存在管理员账户"""
    return User.query.filter_by(is_admin=True).first() is not None 