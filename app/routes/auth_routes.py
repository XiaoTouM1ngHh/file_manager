from flask import render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.urls import url_parse
from app.models import User, db
from app.routes import auth_bp
from app.utils.validators import validate_email, validate_username, validate_password_strength
import logging

# 配置日志
logger = logging.getLogger(__name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录视图"""
    # 已登录用户重定向到首页
    if current_user.is_authenticated:
        return redirect(url_for('file.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        try:
            # 验证用户输入
            if not username or not password:
                flash('用户名和密码不能为空', 'error')
                return render_template('auth/login.html', username=username)
            
            # 查询用户
            user = User.query.filter_by(username=username).first()
            if user is None or not user.verify_password(password):
                flash('用户名或密码不正确', 'error')
                logger.warning(f"登录失败: 用户名: {username}")
                return render_template('auth/login.html', username=username)
            
            # 登录用户
            login_user(user, remember=remember)
            logger.info(f"用户登录成功: {username}")
            
            # 重定向回登录前的页面
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('file.index')
            return redirect(next_page)
        
        except Exception as e:
            logger.error(f"登录视图发生错误: {str(e)}")
            flash('登录时发生错误，请稍后重试', 'error')
            
    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """用户登出视图"""
    try:
        username = current_user.username
        logout_user()
        logger.info(f"用户注销成功: {username}")
        flash('您已成功登出', 'success')
    except Exception as e:
        logger.error(f"注销视图发生错误: {str(e)}")
    
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """用户资料视图"""
    if request.method == 'POST':
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        try:
            # 验证电子邮件格式
            if not validate_email(email):
                flash('电子邮件格式不正确', 'error')
                return render_template('auth/profile.html')
            
            # 检查邮箱是否已被其他用户使用
            user_with_email = User.query.filter_by(email=email).first()
            if user_with_email and user_with_email.id != current_user.id:
                flash('电子邮件已被使用', 'error')
                return render_template('auth/profile.html')
            
            # 更新邮箱
            if email != current_user.email:
                current_user.email = email
                db.session.commit()
                flash('电子邮件更新成功', 'success')
            
            # 如果提供了当前密码，则更新密码
            if current_password:
                # 验证当前密码
                if not current_user.verify_password(current_password):
                    flash('当前密码不正确', 'error')
                    return render_template('auth/profile.html')
                
                # 验证新密码
                if not new_password or not confirm_password:
                    flash('新密码和确认密码都是必填的', 'error')
                    return render_template('auth/profile.html')
                
                if new_password != confirm_password:
                    flash('两次输入的密码不一致', 'error')
                    return render_template('auth/profile.html')
                
                # 验证密码强度
                is_valid, error_msg = validate_password_strength(new_password)
                if not is_valid:
                    flash(error_msg, 'error')
                    return render_template('auth/profile.html')
                
                # 更新密码
                current_user.password = new_password
                db.session.commit()
                flash('密码更新成功', 'success')
                logger.info(f"用户更新了密码: {current_user.username}")
            
            db.session.commit()
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"用户资料更新错误: {str(e)}")
            flash('更新资料时发生错误，请稍后重试', 'error')
    
    return render_template('auth/profile.html') 