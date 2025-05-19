from flask import render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user, login_user
from app.models import User, EncryptionKey, AllowedExtension, FileCategory, db
from app.routes import admin_bp
from app.utils.validators import validate_email, validate_username, validate_password_strength
from app.utils.crypto import generate_key
import logging
import secrets
import string

# 配置日志
logger = logging.getLogger(__name__)


def admin_required(f):
    """管理员权限检查装饰器"""
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('您没有权限访问此页面', 'error')
            logger.warning(f"非管理员用户尝试访问管理页面: {current_user.username}")
            return redirect(url_for('file.index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function


@admin_bp.route('/setup', methods=['GET', 'POST'])
def setup():
    """系统初始化页面 - 创建管理员账户"""
    # 检查是否已有管理员账户
    if User.query.filter_by(is_admin=True).first():
        flash('系统已经有管理员账户了', 'info')
        return redirect(url_for('file.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        try:
            # 验证输入
            if not username or not email or not password or not confirm_password:
                flash('所有字段都是必填的', 'error')
                return render_template('admin/setup.html')
            
            if password != confirm_password:
                flash('两次输入的密码不一致', 'error')
                return render_template('admin/setup.html')
            
            # 验证用户名格式
            if not validate_username(username):
                flash('用户名格式不正确，只能包含字母、数字、下划线和连字符，长度3-20个字符', 'error')
                return render_template('admin/setup.html')
            
            # 验证电子邮件格式
            if not validate_email(email):
                flash('电子邮件格式不正确', 'error')
                return render_template('admin/setup.html')
            
            # 验证密码强度
            is_valid, error_msg = validate_password_strength(password)
            if not is_valid:
                flash(error_msg, 'error')
                return render_template('admin/setup.html')
            
            # 创建管理员用户
            user = User(username=username, email=email, is_admin=True)
            user.password = password
                
            db.session.add(user)
            db.session.commit()
            
            # 初始化默认的文件类型和分类
            init_default_extensions()
            init_default_categories()
            
            logger.info(f"系统初始化: 管理员账户 {username} 创建成功")
            flash('管理员账户创建成功，系统初始化完成', 'success')
            
            # 自动登录管理员
            login_user(user)
            
            return redirect(url_for('admin.index'))
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"系统初始化错误: {str(e)}")
            flash('系统初始化过程中发生错误，请稍后重试', 'error')
    
    return render_template('admin/setup.html')


def init_default_extensions():
    """初始化默认允许的文件扩展名"""
    default_extensions = ['txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 
                         'jpg', 'jpeg', 'png', 'gif', 'zip', 'rar']
    
    for ext in default_extensions:
        if not AllowedExtension.query.filter_by(extension=ext).first():
            extension = AllowedExtension(extension=ext)
            db.session.add(extension)
    
    db.session.commit()
    logger.info("默认文件扩展名初始化完成")


def init_default_categories():
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
    logger.info("默认文件分类初始化完成")


@admin_bp.route('/')
@admin_required
def index():
    """管理员面板首页"""
    try:
        users_count = User.query.count()
        keys_count = EncryptionKey.query.count()
        extensions_count = AllowedExtension.query.count()
        categories_count = FileCategory.query.count()
        
        return render_template('admin/index.html', 
                            users_count=users_count,
                            keys_count=keys_count,
                            extensions_count=extensions_count,
                            categories_count=categories_count)
    except Exception as e:
        logger.error(f"管理员面板加载错误: {str(e)}")
        flash('加载管理员面板时发生错误', 'error')
        return redirect(url_for('file.index'))


# 用户管理
@admin_bp.route('/users')
@admin_required
def users():
    """用户管理视图"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10
        pagination = User.query.paginate(page=page, per_page=per_page)
        return render_template('admin/users.html', users=pagination, pagination=pagination)
    except Exception as e:
        logger.error(f"用户管理视图加载错误: {str(e)}")
        flash('加载用户列表时发生错误', 'error')
        return redirect(url_for('admin.index'))


@admin_bp.route('/users/create', methods=['GET', 'POST'])
@admin_required
def create_user():
    """创建用户视图"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        is_admin = request.form.get('is_admin') == 'on'
        
        try:
            # 验证输入
            if not username or not email or not password or not confirm_password:
                flash('所有字段都是必填的', 'error')
                return render_template('admin/create_user.html', username=username, email=email)
            
            if password != confirm_password:
                flash('两次输入的密码不一致', 'error')
                return render_template('admin/create_user.html', username=username, email=email)
            
            # 验证用户名格式
            if not validate_username(username):
                flash('用户名格式不正确，只能包含字母、数字、下划线和连字符，长度3-20个字符', 'error')
                return render_template('admin/create_user.html', username=username, email=email)
            
            # 验证电子邮件格式
            if not validate_email(email):
                flash('电子邮件格式不正确', 'error')
                return render_template('admin/create_user.html', username=username, email=email)
            
            # 验证密码强度
            is_valid, error_msg = validate_password_strength(password)
            if not is_valid:
                flash(error_msg, 'error')
                return render_template('admin/create_user.html', username=username, email=email)
            
            # 检查用户名和邮箱是否已存在
            if User.query.filter_by(username=username).first():
                flash('用户名已被使用', 'error')
                return render_template('admin/create_user.html', email=email)
            
            if User.query.filter_by(email=email).first():
                flash('电子邮件已被注册', 'error')
                return render_template('admin/create_user.html', username=username)
            
            # 创建新用户
            user = User(username=username, email=email, is_admin=is_admin)
            user.password = password
            
            db.session.add(user)
            db.session.commit()
            
            logger.info(f"管理员创建了新用户: {username}, 管理员权限: {is_admin}")
            flash(f'用户 {username} 创建成功', 'success')
            return redirect(url_for('admin.users'))
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"创建用户时发生错误: {str(e)}")
            flash('创建用户时发生错误，请稍后重试', 'error')
    
    return render_template('admin/create_user.html')


@admin_bp.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    """编辑用户视图"""
    user = User.query.get_or_404(user_id)
    
    # 防止删除唯一的管理员账户
    if user.is_admin and User.query.filter_by(is_admin=True).count() == 1 and user.id != current_user.id:
        flash('不能修改唯一的管理员账户', 'error')
        return redirect(url_for('admin.users'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        is_admin = request.form.get('is_admin') == 'on'
        
        try:
            # 验证电子邮件格式
            if not validate_email(email):
                flash('电子邮件格式不正确', 'error')
                return render_template('admin/edit_user.html', user=user)
            
            # 检查邮箱是否已被其他用户使用
            user_with_email = User.query.filter_by(email=email).first()
            if user_with_email and user_with_email.id != user.id:
                flash('电子邮件已被使用', 'error')
                return render_template('admin/edit_user.html', user=user)
            
            # 更新用户信息
            user.email = email
            
            # 如果是最后一个管理员，不允许取消管理员权限
            if user.is_admin and not is_admin and User.query.filter_by(is_admin=True).count() == 1:
                flash('无法取消唯一管理员的权限', 'error')
            else:
                user.is_admin = is_admin
            
            db.session.commit()
            logger.info(f"管理员更新了用户信息: {user.username}")
            flash(f'用户 {user.username} 更新成功', 'success')
            return redirect(url_for('admin.users'))
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"更新用户信息时发生错误: {str(e)}")
            flash('更新用户信息时发生错误，请稍后重试', 'error')
    
    return render_template('admin/edit_user.html', user=user)


@admin_bp.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """删除用户视图"""
    user = User.query.get_or_404(user_id)
    
    try:
        # 防止删除自己
        if user.id == current_user.id:
            flash('不能删除当前登录的用户', 'error')
            return redirect(url_for('admin.users'))
        
        # 防止删除唯一的管理员账户
        if user.is_admin and User.query.filter_by(is_admin=True).count() == 1:
            flash('不能删除唯一的管理员账户', 'error')
            return redirect(url_for('admin.users'))
        
        username = user.username
        db.session.delete(user)
        db.session.commit()
        
        logger.info(f"管理员删除了用户: {username}")
        flash(f'用户 {username} 已删除', 'success')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"删除用户时发生错误: {str(e)}")
        flash('删除用户时发生错误，请稍后重试', 'error')
    
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/reset-password/<int:user_id>', methods=['POST'])
@admin_required
def reset_password(user_id):
    """重置用户密码视图"""
    user = User.query.get_or_404(user_id)
    
    try:
        # 生成随机密码
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(chars) for _ in range(12))
        
        # 更新用户密码
        user.password = password
        db.session.commit()
        
        logger.info(f"管理员重置了用户密码: {user.username}")
        flash(f'已重置 {user.username} 的密码为: {password}', 'success')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"重置密码时发生错误: {str(e)}")
        flash('重置密码时发生错误，请稍后重试', 'error')
    
    return redirect(url_for('admin.users'))


# 密钥管理
@admin_bp.route('/keys')
@admin_required
def encryption_keys():
    """密钥管理视图"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10
        keys = EncryptionKey.query.paginate(page=page, per_page=per_page)
        return render_template('admin/keys.html', keys=keys)
    except Exception as e:
        logger.error(f"密钥管理视图加载错误: {str(e)}")
        flash('加载密钥列表时发生错误', 'error')
        return redirect(url_for('admin.index'))


@admin_bp.route('/keys/create', methods=['GET', 'POST'])
@admin_required
def create_key():
    """创建密钥视图"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        password = request.form.get('password')
        
        try:
            if not name or not password:
                flash('名称和密码是必填项', 'error')
                return render_template('admin/create_key.html', name=name, description=description)
            
            # 检查名称是否已存在
            if EncryptionKey.query.filter_by(name=name).first():
                flash('密钥名称已存在', 'error')
                return render_template('admin/create_key.html', name=name, description=description)
            
            # 生成密钥
            key_value, salt = generate_key(password)
            
            # 创建密钥记录
            key = EncryptionKey(
                name=name,
                key_value=f"{key_value}:{salt}",  # 存储密钥和盐值
                description=description,
                user_id=current_user.id
            )
            
            db.session.add(key)
            db.session.commit()
            
            logger.info(f"管理员创建了新密钥: {name}")
            flash(f'密钥 {name} 创建成功', 'success')
            return redirect(url_for('admin.encryption_keys'))
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"创建密钥时发生错误: {str(e)}")
            flash('创建密钥时发生错误，请稍后重试', 'error')
    
    return render_template('admin/create_key.html')


@admin_bp.route('/keys/edit/<int:key_id>', methods=['GET', 'POST'])
@admin_required
def edit_key(key_id):
    """编辑密钥视图"""
    key = EncryptionKey.query.get_or_404(key_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        try:
            if not name:
                flash('名称是必填项', 'error')
                return render_template('admin/edit_key.html', key=key)
            
            # 检查名称是否已被其他密钥使用
            key_with_name = EncryptionKey.query.filter_by(name=name).first()
            if key_with_name and key_with_name.id != key.id:
                flash('密钥名称已存在', 'error')
                return render_template('admin/edit_key.html', key=key)
            
            # 更新密钥信息
            key.name = name
            key.description = description
            
            db.session.commit()
            logger.info(f"管理员更新了密钥信息: {name}")
            flash(f'密钥 {name} 更新成功', 'success')
            return redirect(url_for('admin.encryption_keys'))
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"更新密钥信息时发生错误: {str(e)}")
            flash('更新密钥信息时发生错误，请稍后重试', 'error')
    
    return render_template('admin/edit_key.html', key=key)


@admin_bp.route('/keys/delete/<int:key_id>', methods=['POST'])
@admin_required
def delete_key(key_id):
    """删除密钥视图"""
    key = EncryptionKey.query.get_or_404(key_id)
    
    try:
        # 检查密钥是否正在使用
        if key.files.count() > 0:
            flash('该密钥正在被文件使用，无法删除', 'error')
            return redirect(url_for('admin.encryption_keys'))
        
        name = key.name
        db.session.delete(key)
        db.session.commit()
        
        logger.info(f"管理员删除了密钥: {name}")
        flash(f'密钥 {name} 已删除', 'success')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"删除密钥时发生错误: {str(e)}")
        flash('删除密钥时发生错误，请稍后重试', 'error')
    
    return redirect(url_for('admin.encryption_keys'))


@admin_bp.route('/keys/download/<int:key_id>')
@admin_required
def download_key(key_id):
    """下载密钥视图"""
    try:
        key = EncryptionKey.query.get_or_404(key_id)
        
        # 生成密钥文件内容
        key_content = f"""# 文件加密密钥
# 密钥名称: {key.name}
# 创建时间: {key.created_at.strftime('%Y-%m-%d %H:%M:%S')}
# 描述: {key.description or '无'}

# 密钥值 (请妥善保管，不要泄露给他人)
{key.key_value}

# 使用说明:
# 1. 将此文件保存到安全的位置
# 2. 使用此密钥可以解密使用该密钥加密的文件
# 3. 请勿将此密钥分享给他人
"""
        
        # 设置响应头
        headers = {
            'Content-Disposition': f'attachment; filename=encryption_key_{key.name}.txt',
            'Content-Type': 'text/plain; charset=utf-8'
        }
        
        logger.info(f"管理员下载了密钥: {key.name}")
        return key_content, 200, headers
        
    except Exception as e:
        logger.error(f"下载密钥时发生错误: {str(e)}")
        flash('下载密钥时发生错误，请稍后重试', 'error')
        return redirect(url_for('admin.encryption_keys'))


# 允许的文件扩展名管理
@admin_bp.route('/extensions')
@admin_required
def extensions():
    """文件扩展名管理视图"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10
        pagination = AllowedExtension.query.paginate(page=page, per_page=per_page)
        return render_template('admin/extensions.html', extensions=pagination.items, pagination=pagination)
    except Exception as e:
        logger.error(f"文件扩展名管理视图加载错误: {str(e)}")
        flash('加载文件扩展名列表时发生错误', 'error')
        return redirect(url_for('admin.index'))


@admin_bp.route('/extensions/create', methods=['POST'])
@admin_required
def create_extension():
    """创建允许的文件扩展名"""
    extension = request.form.get('extension', '').lower().strip()
    
    try:
        if not extension:
            flash('扩展名不能为空', 'error')
            return redirect(url_for('admin.extensions'))
        
        # 去掉可能的前导点
        if extension.startswith('.'):
            extension = extension[1:]
        
        # 检查扩展名是否已存在
        if AllowedExtension.query.filter_by(extension=extension).first():
            flash(f'扩展名 {extension} 已存在', 'error')
            return redirect(url_for('admin.extensions'))
        
        # 创建新扩展名
        ext = AllowedExtension(extension=extension)
        db.session.add(ext)
        db.session.commit()
        
        logger.info(f"管理员添加了新的允许扩展名: {extension}")
        flash(f'扩展名 {extension} 添加成功', 'success')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"添加扩展名时发生错误: {str(e)}")
        flash('添加扩展名时发生错误，请稍后重试', 'error')
    
    return redirect(url_for('admin.extensions'))


@admin_bp.route('/extensions/edit/<int:extension_id>', methods=['POST'])
@admin_required
def edit_extension(extension_id):
    """编辑文件扩展名"""
    ext = AllowedExtension.query.get_or_404(extension_id)
    name = request.form.get('name', '').lower().strip()
    description = request.form.get('description', '')
    icon = request.form.get('icon', '')
    
    try:
        if not name:
            flash('扩展名不能为空', 'error')
            return redirect(url_for('admin.extensions'))
        
        # 去掉可能的前导点
        if name.startswith('.'):
            name = name[1:]
        
        # 检查名称是否已被其他扩展名使用
        ext_with_name = AllowedExtension.query.filter_by(extension=name).first()
        if ext_with_name and ext_with_name.id != ext.id:
            flash(f'扩展名 {name} 已存在', 'error')
            return redirect(url_for('admin.extensions'))
        
        # 更新扩展名信息
        ext.extension = name
        ext.description = description
        ext.icon = icon
        
        db.session.commit()
        logger.info(f"管理员更新了文件扩展名: {name}")
        flash(f'扩展名 {name} 更新成功', 'success')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"更新扩展名时发生错误: {str(e)}")
        flash('更新扩展名时发生错误，请稍后重试', 'error')
    
    return redirect(url_for('admin.extensions'))


@admin_bp.route('/extensions/toggle/<int:ext_id>', methods=['POST'])
@admin_required
def toggle_extension(ext_id):
    """启用/禁用文件扩展名"""
    ext = AllowedExtension.query.get_or_404(ext_id)
    
    try:
        ext.is_active = not ext.is_active
        db.session.commit()
        
        status = "启用" if ext.is_active else "禁用"
        logger.info(f"管理员{status}了扩展名: {ext.extension}")
        flash(f'扩展名 {ext.extension} 已{status}', 'success')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"切换扩展名状态时发生错误: {str(e)}")
        flash('切换扩展名状态时发生错误，请稍后重试', 'error')
    
    return redirect(url_for('admin.extensions'))


@admin_bp.route('/extensions/delete/<int:ext_id>', methods=['POST'])
@admin_required
def delete_extension(ext_id):
    """删除文件扩展名"""
    ext = AllowedExtension.query.get_or_404(ext_id)
    
    try:
        extension = ext.extension
        db.session.delete(ext)
        db.session.commit()
        
        logger.info(f"管理员删除了扩展名: {extension}")
        flash(f'扩展名 {extension} 已删除', 'success')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"删除扩展名时发生错误: {str(e)}")
        flash('删除扩展名时发生错误，请稍后重试', 'error')
    
    return redirect(url_for('admin.extensions'))


# 文件分类管理
@admin_bp.route('/categories')
@admin_required
def categories():
    """文件分类管理视图"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10
        pagination = FileCategory.query.paginate(page=page, per_page=per_page)
        return render_template('admin/categories.html', categories=pagination.items, pagination=pagination)
    except Exception as e:
        logger.error(f"文件分类管理视图加载错误: {str(e)}")
        flash('加载文件分类列表时发生错误', 'error')
        return redirect(url_for('admin.index'))


@admin_bp.route('/categories/create', methods=['POST'])
@admin_required
def create_category():
    """创建文件分类"""
    name = request.form.get('name')
    description = request.form.get('description', '')
    
    try:
        if not name:
            flash('分类名称不能为空', 'error')
            return redirect(url_for('admin.categories'))
        
        # 检查分类是否已存在
        if FileCategory.query.filter_by(name=name).first():
            flash(f'分类 {name} 已存在', 'error')
            return redirect(url_for('admin.categories'))
        
        # 创建新分类
        category = FileCategory(name=name, description=description)
        db.session.add(category)
        db.session.commit()
        
        logger.info(f"管理员创建了新的文件分类: {name}")
        flash(f'分类 {name} 创建成功', 'success')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"创建文件分类时发生错误: {str(e)}")
        flash('创建文件分类时发生错误，请稍后重试', 'error')
    
    return redirect(url_for('admin.categories'))


@admin_bp.route('/categories/edit/<int:category_id>', methods=['GET', 'POST'])
@admin_required
def edit_category(category_id):
    """编辑文件分类"""
    category = FileCategory.query.get_or_404(category_id)
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description', '')
        
        try:
            if not name:
                flash('分类名称不能为空', 'error')
                return render_template('admin/edit_category.html', category=category)
            
            # 检查名称是否已被其他分类使用
            cat_with_name = FileCategory.query.filter_by(name=name).first()
            if cat_with_name and cat_with_name.id != category.id:
                flash('分类名称已存在', 'error')
                return render_template('admin/edit_category.html', category=category)
            
            # 更新分类信息
            category.name = name
            category.description = description
            
            db.session.commit()
            logger.info(f"管理员更新了文件分类: {name}")
            flash(f'分类 {name} 更新成功', 'success')
            return redirect(url_for('admin.categories'))
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"更新文件分类时发生错误: {str(e)}")
            flash('更新文件分类时发生错误，请稍后重试', 'error')
    
    return render_template('admin/edit_category.html', category=category)


@admin_bp.route('/categories/delete/<int:category_id>', methods=['POST'])
@admin_required
def delete_category(category_id):
    """删除文件分类"""
    category = FileCategory.query.get_or_404(category_id)
    
    try:
        # 检查分类是否正在使用
        if category.files.count() > 0:
            flash('该分类下有文件，无法删除', 'error')
            return redirect(url_for('admin.categories'))
        
        name = category.name
        db.session.delete(category)
        db.session.commit()
        
        logger.info(f"管理员删除了文件分类: {name}")
        flash(f'分类 {name} 已删除', 'success')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"删除文件分类时发生错误: {str(e)}")
        flash('删除文件分类时发生错误，请稍后重试', 'error')
    
    return redirect(url_for('admin.categories')) 