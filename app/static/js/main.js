/**
 * 文件管理系统前端JavaScript
 */

// DOM加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    // 初始化弹窗关闭按钮
    initAlertClose();
    
    // 初始化文件上传预览
    initFileUploadPreview();
    
    // 初始化确认对话框
    initConfirmDialogs();
    
    // 初始化文件过滤
    initFileFilter();
});

/**
 * 初始化警告框关闭按钮
 */
function initAlertClose() {
    const closeButtons = document.querySelectorAll('.alert .close');
    closeButtons.forEach(button => {
        button.addEventListener('click', function() {
            const alert = this.closest('.alert');
            alert.classList.add('opacity-0');
            setTimeout(() => {
                alert.style.display = 'none';
            }, 300);
        });
    });
    
    // 自动关闭成功和信息提示
    const autoCloseAlerts = document.querySelectorAll('.alert-success, .alert-info');
    autoCloseAlerts.forEach(alert => {
        setTimeout(() => {
            alert.classList.add('opacity-0');
            setTimeout(() => {
                alert.style.display = 'none';
            }, 300);
        }, 5000);
    });
}

/**
 * 初始化文件上传预览
 */
function initFileUploadPreview() {
    const fileInput = document.getElementById('file-input');
    const filePreview = document.getElementById('file-preview');
    const fileNameInput = document.getElementById('filename');
    
    if (fileInput && filePreview) {
        fileInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                const file = this.files[0];
                const fileType = file.type.split('/')[0];
                
                // 显示文件名
                filePreview.textContent = file.name;
                
                // 如果文件名输入框为空，使用文件名填充
                if (fileNameInput && !fileNameInput.value) {
                    // 去除扩展名
                    const fileName = file.name.split('.').slice(0, -1).join('.');
                    fileNameInput.value = fileName;
                }
            }
        });
    }
}

/**
 * 初始化确认对话框
 */
function initConfirmDialogs() {
    const confirmButtons = document.querySelectorAll('[data-confirm]');
    
    confirmButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            const confirmMessage = this.getAttribute('data-confirm') || '确定要执行此操作吗？';
            if (!confirm(confirmMessage)) {
                event.preventDefault();
            }
        });
    });
}

/**
 * 初始化文件过滤
 */
function initFileFilter() {
    const fileFilter = document.getElementById('file-filter');
    const fileItems = document.querySelectorAll('.file-item');
    
    if (fileFilter && fileItems.length > 0) {
        fileFilter.addEventListener('input', function() {
            const filterText = this.value.toLowerCase().trim();
            
            fileItems.forEach(file => {
                const fileName = file.getAttribute('data-filename').toLowerCase();
                const fileDesc = file.getAttribute('data-description').toLowerCase();
                
                if (fileName.includes(filterText) || fileDesc.includes(filterText)) {
                    file.classList.remove('d-none');
                } else {
                    file.classList.add('d-none');
                }
            });
        });
    }
}

/**
 * 复制文本到剪贴板
 * @param {string} text 要复制的文本
 * @param {HTMLElement} button 触发复制的按钮元素
 */
function copyToClipboard(text, button) {
    navigator.clipboard.writeText(text).then(() => {
        // 保存原始文本
        const originalText = button.textContent;
        const originalClass = button.className;
        
        // 更改按钮文本和样式
        button.textContent = '已复制!';
        button.classList.remove('btn-primary');
        button.classList.add('btn-success');
        
        // 恢复原始文本和样式
        setTimeout(() => {
            button.textContent = originalText;
            button.className = originalClass;
        }, 2000);
    }).catch(err => {
        console.error('复制失败:', err);
        alert('复制失败，请手动复制');
    });
} 