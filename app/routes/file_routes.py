import os
import uuid
import tempfile
from datetime import datetime
from flask import render_template, redirect, url_for, flash, request, send_file, current_app, abort, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app.models import File, FileCategory, EncryptionKey, AllowedExtension, db
from app.routes import file_bp
from app.utils.validators import allowed_file, generate_safe_filename
from app.utils.crypto import encrypt_file, decrypt_file, calculate_md5
import logging
from cryptography.fernet import Fernet

# 配置日志
logger = logging.getLogger(__name__)


@file_bp.route('/')
@login_required
def index():
    """文件管理首页"""
    try:
        # 获取分类列表
        categories = FileCategory.query.all()
        
        # 根据权限获取文件
        if current_user.is_admin:
            files = File.query.order_by(File.created_at.desc()).all()
        else:
            files = File.query.filter_by(user_id=current_user.id).order_by(File.created_at.desc()).all()
        
        return render_template('file/index.html', files=files, categories=categories)
    except Exception as e:
        logger.error(f"文件首页加载错误: {str(e)}")
        flash('加载文件列表时发生错误', 'error')
        return render_template('file/index.html', files=[], categories=[])


@file_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """上传文件视图"""
    try:
        # 获取分类和密钥列表
        categories = FileCategory.query.all()
        if current_user.is_admin:
            keys = EncryptionKey.query.all()
        else:
            keys = EncryptionKey.query.all()
        
        # 获取允许的文件扩展名
        allowed_extensions = {ext.extension for ext in AllowedExtension.query.filter_by(is_active=True).all()}
        
        if request.method == 'POST':
            # 检查上传文件是否存在
            if 'file' not in request.files:
                flash('没有选择文件', 'error')
                return render_template('file/upload.html', categories=categories, keys=keys)
            
            uploaded_file = request.files['file']
            if uploaded_file.filename == '':
                flash('没有选择文件', 'error')
                return render_template('file/upload.html', categories=categories, keys=keys)
            
            # 检查文件扩展名
            if not allowed_file(uploaded_file.filename, allowed_extensions):
                flash('不允许的文件类型', 'error')
                return render_template('file/upload.html', categories=categories, keys=keys)
            
            # 获取表单数据
            filename = request.form.get('filename')
            description = request.form.get('description', '')
            category_id = request.form.get('category_id', type=int)
            encryption_key_id = request.form.get('encryption_key_id', type=int)
            
            # 验证表单数据
            if not filename:
                flash('文件名不能为空', 'error')
                return render_template('file/upload.html', categories=categories, keys=keys)
            
            if not category_id:
                flash('必须选择一个分类', 'error')
                return render_template('file/upload.html', categories=categories, keys=keys)
            
            # 检查分类是否存在
            category = FileCategory.query.get(category_id)
            if not category:
                flash('所选分类不存在', 'error')
                return render_template('file/upload.html', categories=categories, keys=keys)
            
            # 获取加密密钥（如果提供）
            encryption_key = None
            if encryption_key_id:
                encryption_key = EncryptionKey.query.get(encryption_key_id)
                if not encryption_key:
                    flash('所选密钥不存在', 'error')
                    return render_template('file/upload.html', categories=categories, keys=keys)
            
            # 保存文件
            original_filename = secure_filename(uploaded_file.filename)
            file_ext = os.path.splitext(original_filename)[1]
            safe_filename = f"{uuid.uuid4().hex}{file_ext}"
            
            # 创建上传目录（如果不存在）
            upload_folder = current_app.config['UPLOAD_FOLDER']
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            
            # 临时保存上传的文件
            temp_path = os.path.join(tempfile.gettempdir(), safe_filename)
            uploaded_file.save(temp_path)
            
            # 文件大小和MD5哈希
            file_size = os.path.getsize(temp_path)
            
            # 构建保存路径
            year_month = datetime.now().strftime('%Y%m')
            save_dir = os.path.join(upload_folder, year_month)
            if not os.path.exists(save_dir):
                os.makedirs(save_dir)
            
            file_path = os.path.join(save_dir, safe_filename)
            
            # 创建文件记录
            new_file = File(
                filename=filename,
                original_filename=original_filename,
                description=description,
                size=file_size,
                file_path=os.path.join(year_month, safe_filename),
                user_id=current_user.id,
                category_id=category_id,
                is_encrypted=bool(encryption_key)
            )
            
            # 如果需要加密，则加密文件
            if encryption_key:
                new_file.encryption_key_id = encryption_key.id
                
                # 解析密钥和盐值
                key_parts = encryption_key.key_value.split(':')
                if len(key_parts) != 2:
                    flash('密钥格式错误', 'error')
                    os.remove(temp_path)
                    return render_template('file/upload.html', categories=categories, keys=keys)
                
                key_value = key_parts[0]
                
                try:
                    # 加密文件并计算MD5
                    md5_hash = encrypt_file(temp_path, file_path, key_value)
                    new_file.md5 = md5_hash
                except Exception as e:
                    logger.error(f"文件加密失败: {str(e)}")
                    flash('文件加密失败', 'error')
                    os.remove(temp_path)
                    return render_template('file/upload.html', categories=categories, keys=keys)
            else:
                # 不加密，直接保存文件
                os.rename(temp_path, file_path)
                # 计算加密后的MD5（即使不加密也使用相同的加密方式计算MD5）
                try:
                    # 生成临时密钥用于计算MD5
                    temp_key = Fernet.generate_key()
                    temp_encrypted_path = os.path.join(tempfile.gettempdir(), f"temp_encrypted_{safe_filename}")
                    # 加密文件
                    md5_hash = encrypt_file(file_path, temp_encrypted_path, temp_key.decode('utf-8'))
                    new_file.md5 = md5_hash
                    # 清理临时文件
                    if os.path.exists(temp_encrypted_path):
                        os.remove(temp_encrypted_path)
                except Exception as e:
                    logger.error(f"计算文件MD5失败: {str(e)}")
                    flash('计算文件MD5失败', 'error')
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    return render_template('file/upload.html', categories=categories, keys=keys)
            
            # 保存文件记录
            db.session.add(new_file)
            db.session.commit()
            
            # 清理临时文件
            if os.path.exists(temp_path):
                os.remove(temp_path)
            
            logger.info(f"用户 {current_user.username} 上传了文件: {filename}")
            flash('文件上传成功', 'success')
            return redirect(url_for('file.index'))
        
        return render_template('file/upload.html', categories=categories, keys=keys)
    
    except Exception as e:
        logger.error(f"文件上传视图错误: {str(e)}")
        flash('文件上传时发生错误', 'error')
        return redirect(url_for('file.index'))


@file_bp.route('/files/<file_guid>')
@login_required
def file_details(file_guid):
    """文件详情视图"""
    try:
        file = File.query.filter_by(guid=file_guid).first_or_404()
        
        # 检查权限
        if not current_user.is_admin and file.user_id != current_user.id:
            logger.warning(f"用户 {current_user.username} 尝试访问无权限的文件: {file.filename}")
            abort(403)
        
        return render_template('file/details.html', file=file)
    
    except Exception as e:
        logger.error(f"文件详情视图错误: {str(e)}")
        flash('获取文件详情时发生错误', 'error')
        return redirect(url_for('file.index'))


@file_bp.route('/files/<file_guid>/edit', methods=['GET', 'POST'])
@login_required
def edit_file(file_guid):
    """编辑文件视图"""
    try:
        file = File.query.filter_by(guid=file_guid).first_or_404()
        
        # 检查权限
        if not current_user.is_admin and file.user_id != current_user.id:
            logger.warning(f"用户 {current_user.username} 尝试编辑无权限的文件: {file.filename}")
            abort(403)
        
        categories = FileCategory.query.all()
        
        if request.method == 'POST':
            filename = request.form.get('filename')
            description = request.form.get('description', '')
            category_id = request.form.get('category_id', type=int)
            
            # 验证表单数据
            if not filename:
                flash('文件名不能为空', 'error')
                return render_template('file/edit.html', file=file, categories=categories)
            
            if not category_id:
                flash('必须选择一个分类', 'error')
                return render_template('file/edit.html', file=file, categories=categories)
            
            # 检查分类是否存在
            category = FileCategory.query.get(category_id)
            if not category:
                flash('所选分类不存在', 'error')
                return render_template('file/edit.html', file=file, categories=categories)
            
            # 更新文件信息
            file.filename = filename
            file.description = description
            file.category_id = category_id
            
            db.session.commit()
            
            logger.info(f"用户 {current_user.username} 更新了文件: {filename}")
            flash('文件信息更新成功', 'success')
            return redirect(url_for('file.file_details', file_guid=file.guid))
        
        return render_template('file/edit.html', file=file, categories=categories)
    
    except Exception as e:
        logger.error(f"编辑文件视图错误: {str(e)}")
        flash('编辑文件信息时发生错误', 'error')
        return redirect(url_for('file.index'))


@file_bp.route('/files/<file_guid>/download')
@login_required
def download_file(file_guid):
    """下载文件视图"""
    try:
        file = File.query.filter_by(guid=file_guid).first_or_404()
        
        # 检查权限
        if not current_user.is_admin and file.user_id != current_user.id:
            logger.warning(f"用户 {current_user.username} 尝试下载无权限的文件: {file.filename}")
            abort(403)
        
        # 获取完整的文件路径
        full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.file_path)
        
        if not os.path.exists(full_path):
            logger.error(f"文件 {file.filename} 不存在于路径: {full_path}")
            flash('文件不存在或已被删除', 'error')
            return redirect(url_for('file.index'))
        
        # 如果文件已加密，则需要先解密
        if file.is_encrypted and file.encryption_key:
            # 创建临时文件用于解密
            temp_dir = tempfile.gettempdir()
            temp_filename = f"decrypted_{uuid.uuid4().hex}{os.path.splitext(file.original_filename)[1]}"
            temp_path = os.path.join(temp_dir, temp_filename)
            
            # 解析密钥
            key_parts = file.encryption_key.key_value.split(':')
            if len(key_parts) != 2:
                flash('密钥格式错误，无法解密文件', 'error')
                return redirect(url_for('file.file_details', file_guid=file.guid))
            
            key_value = key_parts[0]
            
            # 解密文件
            if not decrypt_file(full_path, temp_path, key_value):
                flash('文件解密失败', 'error')
                return redirect(url_for('file.file_details', file_guid=file.guid))
            
            # 记录下载日志
            logger.info(f"用户 {current_user.username} 下载了文件: {file.filename}")
            
            # 发送解密后的临时文件
            return send_file(
                temp_path,
                as_attachment=True,
                download_name=file.original_filename,
                max_age=0
            )
        else:
            # 记录下载日志
            logger.info(f"用户 {current_user.username} 下载了文件: {file.filename}")
            
            # 直接发送未加密的文件
            return send_file(
                full_path,
                as_attachment=True,
                download_name=file.original_filename,
                max_age=0
            )
    
    except Exception as e:
        logger.error(f"文件下载错误: {str(e)}")
        flash('下载文件时发生错误', 'error')
        return redirect(url_for('file.index'))


@file_bp.route('/files/<file_guid>/delete', methods=['POST'])
@login_required
def delete_file(file_guid):
    """删除文件视图"""
    try:
        file = File.query.filter_by(guid=file_guid).first_or_404()
        
        # 检查权限
        if not current_user.is_admin and file.user_id != current_user.id:
            logger.warning(f"用户 {current_user.username} 尝试删除无权限的文件: {file.filename}")
            abort(403)
        
        # 获取文件路径
        full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.file_path)
        
        # 删除物理文件
        if os.path.exists(full_path):
            os.remove(full_path)
        
        # 保存文件名以便在日志中使用
        filename = file.filename
        
        # 删除数据库记录
        db.session.delete(file)
        db.session.commit()
        
        logger.info(f"用户 {current_user.username} 删除了文件: {filename}")
        flash('文件删除成功', 'success')
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"删除文件时发生错误: {str(e)}")
        flash('删除文件时发生错误', 'error')
    
    return redirect(url_for('file.index'))


@file_bp.route('/files/by-category/<int:category_id>')
@login_required
def files_by_category(category_id):
    """按分类查看文件"""
    try:
        category = FileCategory.query.get_or_404(category_id)
        categories = FileCategory.query.all()
        
        # 根据权限获取文件
        if current_user.is_admin:
            files = File.query.filter_by(category_id=category_id).order_by(File.created_at.desc()).all()
        else:
            files = File.query.filter_by(category_id=category_id, user_id=current_user.id).order_by(File.created_at.desc()).all()
        
        return render_template('file/index.html', files=files, categories=categories, current_category=category)
    
    except Exception as e:
        logger.error(f"按分类查看文件视图错误: {str(e)}")
        flash('加载分类文件时发生错误', 'error')
        return redirect(url_for('file.index')) 