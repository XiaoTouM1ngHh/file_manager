from flask import jsonify, request, send_file, current_app, abort
from app.models import FileCategory, File
from app.routes import api_bp
import os
import logging

# 配置日志
logger = logging.getLogger(__name__)


@api_bp.route('/', methods=['GET'])
def api_index():
    """
    API根路径，返回API基本信息
    
    返回:
        JSON: API基本信息
    """
    try:
        return jsonify({
            'success': True,
            'data': {
                'name': '文件管理系统API',
                'version': '1.0.0',
                'endpoints': {
                    'files': {
                        'count': '/files/count',
                        'attributes': '/files/<file_guid>',
                        'content': '/files/<file_guid>/content'
                    },
                    'categories': {
                        'list': '/categories',
                        'files': '/categories/<category_id>/files'
                    }
                }
            }
        }), 200
    except Exception as e:
        logger.error(f"API根路径访问错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': '获取API信息失败',
            'error': str(e)
        }), 500


@api_bp.route('/files/count', methods=['GET'])
def get_files_count():
    """
    获取系统中的文件总数
    
    返回:
        JSON: 包含文件总数的响应
    """
    try:
        total_files = File.query.count()
        return jsonify({
            'success': True,
            'data': {
                'total': total_files
            }
        }), 200
    except Exception as e:
        logger.error(f"API获取文件总数错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': '获取文件总数失败',
            'error': str(e)
        }), 500


@api_bp.route('/categories', methods=['GET'])
def get_categories():
    """
    获取所有分类
    
    返回:
        JSON: 所有分类的列表
    """
    try:
        categories = FileCategory.query.all()
        return jsonify({
            'success': True,
            'data': [
                {
                    'id': category.id,
                    'name': category.name,
                    'description': category.description
                }
                for category in categories
            ]
        }), 200
    except Exception as e:
        logger.error(f"API获取分类错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': '获取分类失败',
            'error': str(e)
        }), 500


@api_bp.route('/categories/<int:category_id>/files', methods=['GET'])
def get_files_by_category(category_id):
    """
    获取分类下所有文件（GUID）
    
    参数:
        category_id (int): 分类ID
        
    返回:
        JSON: 分类下所有文件的GUID列表
    """
    try:
        category = FileCategory.query.get_or_404(category_id)
        files = File.query.filter_by(category_id=category_id).all()
        
        return jsonify({
            'success': True,
            'data': {
                'category': {
                    'id': category.id,
                    'name': category.name,
                    'description': category.description
                },
                'files': [
                    {
                        'guid': file.guid,
                        'filename': file.filename
                    }
                    for file in files
                ]
            }
        }), 200
    except Exception as e:
        logger.error(f"API获取分类文件错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': '获取分类文件失败',
            'error': str(e)
        }), 500


@api_bp.route('/files/<file_guid>', methods=['GET'])
def get_file_attributes(file_guid):
    """
    获取指定文件属性（文件名、文件说明、分类、大小、md5）
    
    参数:
        file_guid (str): 文件GUID
        
    返回:
        JSON: 文件属性
    """
    try:
        file = File.query.filter_by(guid=file_guid).first_or_404()
        
        # 格式化文件大小
        size_kb = file.size / 1024
        if size_kb < 1024:
            size_str = f"{size_kb:.2f} KB"
        else:
            size_mb = size_kb / 1024
            if size_mb < 1024:
                size_str = f"{size_mb:.2f} MB"
            else:
                size_gb = size_mb / 1024
                size_str = f"{size_gb:.2f} GB"
        
        # 获取文件扩展名
        _, extension = os.path.splitext(file.original_filename)
        extension = extension[1:] if extension else ""
        
        return jsonify({
            'success': True,
            'data': {
                'guid': file.guid,
                'filename': file.filename,
                'extension': extension,
                'description': file.description,
                'category': {
                    'id': file.category.id,
                    'name': file.category.name
                },
                'size': file.size,
                'size_formatted': size_str,
                'md5': file.md5,
                'is_encrypted': file.is_encrypted,
                'created_at': file.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'updated_at': file.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        }), 200
    except Exception as e:
        logger.error(f"API获取文件属性错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': '获取文件属性失败',
            'error': str(e)
        }), 500


@api_bp.route('/files/<file_guid>/content', methods=['GET'])
def get_file_content(file_guid):
    """
    获取文件内容（不解密）
    
    参数:
        file_guid (str): 文件GUID
        
    返回:
        File: 文件内容
    """
    try:
        file = File.query.filter_by(guid=file_guid).first_or_404()
        
        # 获取完整的文件路径
        full_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.file_path)
        
        if not os.path.exists(full_path):
            logger.error(f"API获取文件内容: 文件 {file.filename} 不存在于路径: {full_path}")
            return jsonify({
                'success': False,
                'message': '文件不存在或已被删除'
            }), 404
        
        # 记录API访问日志
        logger.info(f"API访问了文件内容: {file.filename}")
        
        # 发送文件
        return send_file(
            full_path,
            as_attachment=True,
            download_name=file.original_filename,
            max_age=0
        )
    except Exception as e:
        logger.error(f"API获取文件内容错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': '获取文件内容失败',
            'error': str(e)
        }), 500 