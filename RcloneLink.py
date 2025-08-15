#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import sys
import os
import json
import subprocess
import threading
import time
import webbrowser
import winreg
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox,
    QCheckBox, QGroupBox, QFormLayout, QMessageBox, QProgressBar,
    QFileDialog, QSplitter, QTableWidget, QTableWidgetItem,QRadioButton,
    QScrollArea, QFrame, QDialog, QListWidget, QSystemTrayIcon, QMenu, QInputDialog, QHeaderView, QDialogButtonBox
)
from PySide6.QtCore import Qt, QThread, QObject, Signal, QTimer, QProcess
from PySide6.QtGui import QFont, QIcon, QPalette, QColor, QAction
from PySide6.QtNetwork import QLocalServer, QLocalSocket

# 导入 ctypes 用于检查管理员权限
import ctypes
from mounts import get_column_headers, populate_mount_table_row, read_mount_options_from_row, build_mount_command, start_mount_all, RCloneMountWorker, get_default_mount_options, get_next_available_drive, get_next_available_drive, get_next_available_drive


class RCloneConfigWorker(QObject):
    """RClone配置工作线程"""
    output_signal = Signal(str)
    finished_signal = Signal(bool, str)

    def __init__(self, rclone_path: str):
        super().__init__()
        self.rclone_path = rclone_path
        self.process = None

    def configure_webdav(self, config: Dict):
        """配置WebDAV远程"""
        try:
            success = self.create_config_file(config)
            if success:
                self.output_signal.emit("配置文件创建成功!")
                self.finished_signal.emit(True, "WebDAV配置成功")
            else:
                self.finished_signal.emit(False, "配置文件创建失败")

        except Exception as e:
            self.output_signal.emit(f"配置错误: {str(e)}")
            self.finished_signal.emit(False, f"配置错误: {str(e)}")

    def create_config_file(self, config: Dict) -> bool:
        """直接创建rclone配置文件"""
        try:
            config_dir = self.get_rclone_config_dir()
            config_file = os.path.join(config_dir, "rclone.conf")

            self.output_signal.emit(f"配置文件路径: {config_file}")

            os.makedirs(config_dir, exist_ok=True)

            encrypted_password = self.encrypt_password(config['password'])

            config_content = f"""[{config['name']}]\ntype = webdav\nurl = {config['url']}\nvendor = {self.get_vendor_name(config.get('vendor', '7'))}\nuser = {config['username']}\npass = {encrypted_password}"""

            if config.get('no_check_certificate', False):
                config_content += "\nno_check_certificate = true"

            config_content += "\n"

            existing_config = ""
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    existing_config = f.read()
                self.output_signal.emit("发现现有配置文件，将追加新配置")

            if f"[{config['name']}]" in existing_config:
                self.output_signal.emit(f"警告: 远程 '{config['name']}' 已存在，将覆盖")
                existing_config = self.remove_existing_remote(existing_config, config['name'])

            final_config = existing_config + "\n" + config_content if existing_config else config_content

            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(final_config)

            self.output_signal.emit(f"配置已写入: {config_file}")

            return self.verify_config(config['name'])

        except Exception as e:
            self.output_signal.emit(f"创建配置文件失败: {str(e)}")
            return False

    def get_rclone_config_dir(self) -> str:
        """获取rclone配置目录"""
        if sys.platform == "win32":
            return os.path.join(os.environ.get('APPDATA', ''), 'rclone')
        else:
            home = os.path.expanduser("~")
            return os.path.join(home, '.config', 'rclone')

    def encrypt_password(self, password: str) -> str:
        """使用rclone obscure命令加密密码"""
        try:
            # Add creationflags to hide console window
            creation_flags = 0
            if sys.platform == 'win32':
                creation_flags = subprocess.CREATE_NO_WINDOW

            result = subprocess.run(
                [self.rclone_path, 'obscure', password],
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8',
                errors='ignore',
                creationflags=creation_flags
            )
            if result.returncode == 0:
                encrypted = result.stdout.strip()
                self.output_signal.emit("密码已加密")
                return encrypted
            else:
                self.output_signal.emit("密码加密失败，使用手动加密")
                import base64
                encoded = base64.b64encode(password.encode('utf-8')).decode('ascii')
                return encoded
        except Exception as e:
            self.output_signal.emit(f"密码加密出错，使用手动加密: {str(e)}")
            import base64
            encoded = base64.b64encode(password.encode('utf-8')).decode('ascii')
            return encoded

    def get_vendor_name(self, vendor_code: str) -> str:
        """根据供应商代码获取名称"""
        vendor_map = {
            '1': 'fastmail',
            '2': 'nextcloud',
            '3': 'owncloud',
            '4': 'infinitescale',
            '5': 'sharepoint',
            '6': 'sharepoint-ntlm',
            '7': 'rclone',
            '8': 'other'
        }
        return vendor_map.get(vendor_code, 'rclone')

    def remove_existing_remote(self, config_content: str, remote_name: str) -> str:
        """从配置中移除已存在的远程"""
        lines = config_content.split('\n')
        result_lines = []
        skip_section = False

        for line in lines:
            if line.strip().startswith('[') and line.strip().endswith(']'):
                section_name = line.strip()[1:-1]
                skip_section = (section_name == remote_name)

            if not skip_section:
                result_lines.append(line)

        return '\n'.join(result_lines)

    def verify_config(self, remote_name: str) -> bool:
        """验证配置是否成功"""
        try:
            creation_flags = 0
            if sys.platform == 'win32':
                creation_flags = subprocess.CREATE_NO_WINDOW

            result = subprocess.run(
                [self.rclone_path, 'listremotes'],
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8',
                errors='ignore',
                creationflags=creation_flags
            )

            if result.returncode == 0 and result.stdout:
                remotes = result.stdout.strip().split('\n')
                remotes = [remote.strip() for remote in remotes if remote.strip()]
                remote_found = any(remote.rstrip(':') == remote_name for remote in remotes)

                if remote_found:
                    self.output_signal.emit(f"验证成功: 远程 '{remote_name}' 已配置")
                    return True
                else:
                    self.output_signal.emit(f"验证失败: 未找到远程 '{remote_name}'")
                    self.output_signal.emit(f"当前远程列表: {', '.join([r.rstrip(':') for r in remotes])}")
                    return False
            else:
                error_msg = result.stderr if result.stderr else "未知错误"
                self.output_signal.emit(f"验证失败: {error_msg}")
                return False

        except Exception as e:
            self.output_signal.emit(f"验证配置时出错: {str(e)}")
            return False


class DefaultMountSettingsDialog(QDialog):
    """默认参数设置对话框"""
    def __init__(self, current_settings, parent=None):
        super().__init__(parent)
        self.settings = current_settings.copy()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("默认参数")
        self.setMinimumWidth(500)
        
        main_layout = QVBoxLayout(self)
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        
        container = QWidget()
        layout = QVBoxLayout(container)
        
        self.edits = {}

        param_groups = {
            "基本参数": {
                "cache_dir": "缓存路径   ",
                "log_level": "日志级别",
                "network_mode": "网络模式",
            },
            "缓存优化": {
                "vfs_cache_mode": "缓存模式",
                "vfs_cache_max_size": "缓存容量",
                "vfs_cache_max_age": "缓存有效期",
                "vfs_cache_poll_interval": "轮询间隔",
                "dir_cache_time": "目录有效期",
            },
            "读写性能": {
                "vfs_read_ahead": "预读大小",
                "vfs_read_chunk_size": "读块大小",
                "vfs_read_chunk_size_limit": "读块限制",
                "buffer_size": "缓冲区大小",
                "transfers": "传输线程数",
                "multi_thread_streams": "多线程流",
            },
            "超时与重试": {
                "timeout": "超时时间   ",
                "contimeout": "连接超时",
                "retries": "重试次数",
                "retries_sleep": "重试间隔",
            }
        }

        for group_title, params in param_groups.items():
            group_box = QGroupBox(group_title)
            form_layout = QFormLayout()
            
            for key, label in params.items():
                if key == "cache_dir":
                    path_row = QHBoxLayout()
                    path_edit = QLineEdit(self.settings.get(key, ""))
                    path_edit.setFixedHeight(30)
                    self.edits[key] = path_edit
                    
                    browse_btn = QPushButton("浏览")
                    browse_btn.setFixedHeight(30)
                    browse_btn.clicked.connect(self.browse_cache_dir)
                    
                    path_row.addWidget(path_edit)
                    path_row.addWidget(browse_btn)
                    
                    form_layout.addRow(label, path_row)
                elif key == "log_level":
                    widget = QComboBox()
                    widget.setFixedHeight(30)
                    widget.addItems(["ERROR", "NOTICE", "INFO", "DEBUG"])
                    widget.setCurrentText(self.settings.get(key, "INFO"))
                    form_layout.addRow(label, widget)
                    self.edits[key] = widget
                elif key == "vfs_cache_mode":
                    widget = QComboBox()
                    widget.setFixedHeight(30)
                    widget.addItems(["off", "minimal", "writes", "full"])
                    widget.setCurrentText(self.settings.get(key, "full"))
                    form_layout.addRow(label, widget)
                    self.edits[key] = widget
                elif key == "network_mode":
                    widget = QCheckBox("启用")
                    widget.setChecked(self.settings.get(key, True))
                    form_layout.addRow(label, widget)
                    self.edits[key] = widget
                else:
                    widget = QLineEdit(str(self.settings.get(key, "")))
                    widget.setFixedHeight(30)
                    form_layout.addRow(label, widget)
                    self.edits[key] = widget
            
            group_box.setLayout(form_layout)
            layout.addWidget(group_box)

        button_layout = QHBoxLayout()
        save_btn = QPushButton("保存")
        save_btn.setFixedHeight(30)
        save_btn.clicked.connect(self.save_settings)
        cancel_btn = QPushButton("取消")
        cancel_btn.setFixedHeight(30)
        cancel_btn.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        
        scroll_area.setWidget(container)
        main_layout.addWidget(scroll_area)
        main_layout.addLayout(button_layout)

    def browse_cache_dir(self):
        """浏览缓存目录"""
        directory = QFileDialog.getExistingDirectory(
            self, "选择缓存目录",
            self.edits["cache_dir"].text()
        )
        if directory:
            self.edits["cache_dir"].setText(directory)

    def save_settings(self):
        """保存设置"""
        for key, widget in self.edits.items():
            if isinstance(widget, QLineEdit):
                self.settings[key] = widget.text()
            elif isinstance(widget, QComboBox):
                self.settings[key] = widget.currentText()
            elif isinstance(widget, QCheckBox):
                self.settings[key] = widget.isChecked()
        self.accept()

    def get_settings(self):
        """获取更新后的设置"""
        return self.settings


class AddConfigDialog(QDialog):
    """添加配置对话框"""
    def __init__(self, rclone_path: str, parent=None):
        super().__init__(parent)
        self.rclone_path = rclone_path
        self.init_ui()
        self.config_worker = None
        selfuaa_thread = None

    def init_ui(self):
        self.setWindowTitle("添加新配置")
        layout = QVBoxLayout()

        form_group = QGroupBox("新WebDAV配置")
        form_layout = QFormLayout()

        self.remote_name_edit = QLineEdit()
        self.remote_name_edit.setFixedHeight(30)
        self.remote_name_edit.setPlaceholderText("远程名称")

        self.webdav_url_edit = QLineEdit()
        self.webdav_url_edit.setFixedHeight(30)
        self.webdav_url_edit.setPlaceholderText("WebDAV URL")

        self.username_edit = QLineEdit()
        self.username_edit.setFixedHeight(30)
        self.username_edit.setPlaceholderText("用户名")

        self.password_edit = QLineEdit()
        self.password_edit.setFixedHeight(30)
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("密码")

        self.vendor_combo = QComboBox()
        self.vendor_combo.setFixedHeight(30)
        vendors = [
            ("1", "Fastmail Files"),
            ("2", "Nextcloud"),
            ("3", "Owncloud 10"),
            ("4", "ownCloud Infinite Scale"),
            ("5", "Sharepoint Online"),
            ("6", "Sharepoint NTLM"),
            ("7", "rclone WebDAV server"),
            ("8", "Other site/service")
        ]
        for value, text in vendors:
            self.vendor_combo.addItem(text, value)
        self.vendor_combo.setCurrentIndex(6)

        self.no_check_cert = QCheckBox("跳过SSL证书验证")
        self.no_check_cert.setChecked(True)

        form_layout.addRow("远程名称", self.remote_name_edit)
        form_layout.addRow("WebDAV URL:", self.webdav_url_edit)
        form_layout.addRow("用户名:", self.username_edit)
        form_layout.addRow("密码:", self.password_edit)
        form_layout.addRow("供应商:", self.vendor_combo)
        form_layout.addRow("SSL选项:", self.no_check_cert)

        form_group.setLayout(form_layout)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setMaximumHeight(100)

        button_layout = QHBoxLayout()
        save_btn = QPushButton("保存")
        save_btn.setFixedHeight(30)
        save_btn.clicked.connect(self.save_config)
        cancel_btn = QPushButton("取消")
        cancel_btn.setFixedHeight(30)
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)

        layout.addWidget(form_group)
        layout.addWidget(QLabel("配置日志:"))
        layout.addWidget(self.output_text)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def save_config(self):
        """保存新配置"""
        if not self.validate_inputs():
            return

        config = {
            'name': self.remote_name_edit.text(),
            'url': self.webdav_url_edit.text(),
            'username': self.username_edit.text(),
            'password': self.password_edit.text(),
            'vendor': self.vendor_combo.currentData(),
            'no_check_certificate': self.no_check_cert.isChecked()
        }

        self.config_thread = QThread()
        self.config_worker = RCloneConfigWorker(self.rclone_path)
        self.config_worker.moveToThread(self.config_thread)

        self.config_worker.output_signal.connect(self.update_output)
        self.config_worker.finished_signal.connect(self.config_finished)

        self.config_thread.started.connect(
            lambda: self.config_worker.configure_webdav(config)
        )
        self.config_thread.start()

        self.output_text.append("开始配置新远程...")

    def validate_inputs(self):
        """验证输入"""
        if not self.remote_name_edit.text():
            QMessageBox.information(self, "提示", "请输入远程名称")
            return False
        if not self.webdav_url_edit.text():
            QMessageBox.information(self, "提示", "请输入WebDAV URL")
            return False
        if not self.username_edit.text():
            QMessageBox.information(self, "提示", "请输入用户名")
            return False
        if not self.password_edit.text():
            QMessageBox.information(self, "提示", "请输入密码")
            return False
        return True

    def update_output(self, text):
        """更新输出"""
        self.output_text.append(text)

    def config_finished(self, success, message):
        """配置完成"""
        self.output_text.append(f"配置结果: {message}")
        if success:
            self.accept()
        else:
            QMessageBox.information(self, "提示", f"配置失败: {message}")

        if self.config_thread:
            self.config_thread.quit()
            self.config_thread.wait()




class CustomGetItemDialog(QDialog):
    def __init__(self, parent=None, title="", label="", items=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True) # Make it a modal dialog

        self.selected_item = None
        self.ok_pressed = False

        main_layout = QVBoxLayout()

        # Label
        self.label = QLabel(label)
        main_layout.addWidget(self.label)

        # ComboBox
        self.combo_box = QComboBox()
        if items:
            self.combo_box.addItems(items)
        self.combo_box.setFixedHeight(30)
        main_layout.addWidget(self.combo_box)

        # Buttons
        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("确认")
        self.ok_button.setFixedHeight(30)
        self.ok_button.clicked.connect(self.accept_dialog)
        self.cancel_button = QPushButton("取消")
        self.cancel_button.setFixedHeight(30)
        self.cancel_button.clicked.connect(self.reject_dialog)

        button_layout.addWidget(self.ok_button)
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_button)

        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

    def accept_dialog(self):
        self.selected_item = self.combo_box.currentText()
        self.ok_pressed = True
        self.accept()

    def reject_dialog(self):
        self.selected_item = None
        self.ok_pressed = False
        self.reject()

    def get_result(self):
        return self.selected_item, self.ok_pressed


class ConfigTab(QWidget):
    """配置选项卡"""
    rclone_path_changed = Signal(str)

    def __init__(self):
        super().__init__()
        self.init_ui()
        self.config_worker = None
        self.config_thread = None

    def init_ui(self):
        layout = QVBoxLayout()

        path_group = QGroupBox("Rclone路径")
        path_layout = QFormLayout()

        self.rclone_path_edit = QLineEdit()
        self.rclone_path_edit.setFixedHeight(30)
        self.rclone_path_edit.setText("./rclone.exe")
        self.rclone_path_edit.setPlaceholderText("rclone 程序路径")
        self.rclone_path_edit.setStyleSheet("border: 1px solid grey;")
        self.rclone_path_edit.textChanged.connect(self.rclone_path_changed)

        path_browse_btn = QPushButton("浏览")
        path_browse_btn.setFixedHeight(30)
        path_browse_btn.clicked.connect(self.browse_rclone_path)

        path_row = QHBoxLayout()
        path_row.addWidget(self.rclone_path_edit)
        path_row.addWidget(path_browse_btn)

        path_layout.addRow("Rclone   ", path_row)
        path_group.setLayout(path_layout)

        webdav_group = QGroupBox("WebDAV配置")
        webdav_layout = QFormLayout()

        self.remote_name_edit = QLineEdit()
        self.remote_name_edit.setFixedHeight(30)
        self.remote_name_edit.setText("Jellycat")
        self.remote_name_edit.setPlaceholderText("服务名称")

        self.webdav_url_edit = QLineEdit()
        self.webdav_url_edit.setFixedHeight(30)
        self.webdav_url_edit.setText("https://192.168.1.1:443/dav")
        self.webdav_url_edit.setPlaceholderText("https://example.com/dav")

        self.username_edit = QLineEdit()
        self.username_edit.setFixedHeight(30)
        self.username_edit.setText("用户名")
        self.username_edit.setPlaceholderText("用户名")

        self.password_edit = QLineEdit()
        self.password_edit.setFixedHeight(30)
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setText("202508")
        self.password_edit.setPlaceholderText("密码")

        self.vendor_combo = QComboBox()
        self.vendor_combo.setFixedHeight(30)
        vendors = [
            ("1", "Fastmail Files"),
            ("2", "Nextcloud"),
            ("3", "Owncloud 10"),
            ("4", "ownCloud Infinite Scale"),
            ("5", "Sharepoint Online"),
            ("6", "Sharepoint NTLM"),
            ("7", "rclone WebDAV server"),
            ("8", "Other site/service")
        ]
        for value, text in vendors:
            self.vendor_combo.addItem(text, value)
        self.vendor_combo.setCurrentIndex(6)

        self.no_check_cert = QCheckBox("跳过SSL证书验证")
        self.no_check_cert.setChecked(True)

        webdav_layout.addRow("远程名称", self.remote_name_edit)
        webdav_layout.addRow("WebDAV", self.webdav_url_edit)
        webdav_layout.addRow("用户名", self.username_edit)
        webdav_layout.addRow("密码", self.password_edit)
        webdav_layout.addRow("供应商", self.vendor_combo)
        webdav_layout.addRow("SSL选项", self.no_check_cert)

        webdav_group.setLayout(webdav_layout)

        button_layout = QHBoxLayout()

        add_config_btn = QPushButton("添加配置")
        add_config_btn.setFixedHeight(30)
        add_config_btn.clicked.connect(self.add_config)

        list_remotes_btn = QPushButton("远程列表")
        list_remotes_btn.setFixedHeight(30)
        list_remotes_btn.clicked.connect(self.list_remotes)

        remove_remote_btn = QPushButton("移除远程")
        remove_remote_btn.setFixedHeight(30)
        remove_remote_btn.clicked.connect(self.remove_remote)

        button_layout.addWidget(add_config_btn)
        button_layout.addWidget(list_remotes_btn)
        button_layout.addWidget(remove_remote_btn)
        button_layout.addStretch()

        self.config_output = QTextEdit()
        self.config_output.setReadOnly(True)
        self.config_output.setMaximumHeight(100)

        layout.addWidget(path_group)
        layout.addWidget(webdav_group)
        layout.addLayout(button_layout)
        layout.addWidget(QLabel("配置日志"))
        layout.addWidget(self.config_output)
        layout.addStretch()

        self.setLayout(layout)

    def browse_rclone_path(self):
        """浏览RClone可执行文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择RClone可执行文件", "",
            "可执行文件 (*.exe);;所有文件 (*)"
        )
        if file_path:
            self.rclone_path_edit.setText(os.path.abspath(file_path))

    def add_config(self):
        """添加新配置"""
        if not self.rclone_path_edit.text() or not os.path.exists(self.rclone_path_edit.text()):
            QMessageBox.information(self, "提示", "请先指定有效的RClone路径")
            return

        if not self.validate_inputs():
            return

        config = {
            'name': self.remote_name_edit.text(),
            'url': self.webdav_url_edit.text(),
            'username': self.username_edit.text(),
            'password': self.password_edit.text(),
            'vendor': self.vendor_combo.currentData(),
            'no_check_certificate': self.no_check_cert.isChecked()
        }

        self.config_thread = QThread()
        self.config_worker = RCloneConfigWorker(self.rclone_path_edit.text())
        self.config_worker.moveToThread(self.config_thread)

        self.config_worker.output_signal.connect(self.update_output)
        self.config_worker.finished_signal.connect(self.config_finished)

        self.config_thread.started.connect(
            lambda: self.config_worker.configure_webdav(config)
        )
        self.config_thread.start()

        self.config_output.append("开始添加新配置...")

        # Clear input fields after adding configuration
        self.remote_name_edit.clear()
        self.webdav_url_edit.clear()
        self.username_edit.clear()
        self.password_edit.clear()
        self.vendor_combo.setCurrentIndex(6)
        self.no_check_cert.setChecked(True)

    def validate_inputs(self):
        """验证输入"""
        if not self.remote_name_edit.text():
            QMessageBox.information(self, "提示", "请输入远程名称")
            return False

        if not self.webdav_url_edit.text():
            QMessageBox.information(self, "提示", "请输入WebDAV URL")
            return False

        if not self.username_edit.text():
            QMessageBox.information(self, "提示", "请输入用户名")
            return False

        if not self.password_edit.text():
            QMessageBox.information(self, "提示", "请输入密码")
            return False

        return True

    def list_remotes(self):
        """列出所有配置的远程"""
        if not self.rclone_path_edit.text() or not os.path.exists(self.rclone_path_edit.text()):
            QMessageBox.information(self, "提示", "请先指定有效的RClone路径")
            return

        try:
            creation_flags = 0
            if sys.platform == 'win32':
                creation_flags = subprocess.CREATE_NO_WINDOW

            result = subprocess.run(
                [self.rclone_path_edit.text(), 'listremotes'],
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8',
                errors='ignore',
                creationflags=creation_flags
            )

            if result.returncode == 0 and result.stdout:
                remotes = result.stdout.strip().split('\n')
                remotes = [remote.strip().rstrip(':') for remote in remotes if remote.strip()]
                self.config_output.append("当前远程列表:")
                for remote in remotes:
                    self.config_output.append(f"- {remote}")
                if not remotes:
                    self.config_output.append("未找到任何远程配置")
            else:
                error_msg = result.stderr if result.stderr else "未知错误"
                self.config_output.append(f"获取远程列表失败: {error_msg}")
        except Exception as e:
            self.config_output.append(f"获取远程列表失败: {str(e)}")

    def update_output(self, text):
        """更新输出"""
        self.config_output.append(text)

    def config_finished(self, success, message):
        """配置完成"""
        self.config_output.append(f"配置结果: {message}")
        if success:
            QMessageBox.information(self, "成功", "新配置已添加")
            self.list_remotes()  # Refresh remote list after successful configuration
        else:
            QMessageBox.information(self, "提示", f"配置失败: {message}")

        if self.config_thread:
            self.config_thread.quit()
            self.config_thread.wait()

    def get_remotes(self) -> Optional[List[str]]:
        """获取远程列表"""
        if not self.rclone_path_edit.text() or not os.path.exists(self.rclone_path_edit.text()):
            QMessageBox.information(self, "提示", "请先指定有效的RClone路径")
            return None
        try:
            creation_flags = 0
            if sys.platform == 'win32':
                creation_flags = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(
                [self.rclone_path_edit.text(), 'listremotes'],
                capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore',
                creationflags=creation_flags
            )
            if result.returncode == 0 and result.stdout:
                remotes = result.stdout.strip().split('\n')
                return [remote.strip().rstrip(':') for remote in remotes if remote.strip()]
            else:
                error_msg = result.stderr if result.stderr else "未知错误"
                self.config_output.append(f"获取远程列表失败: {error_msg}")
                return []
        except Exception as e:
            self.config_output.append(f"获取远程列表失败: {str(e)}")
            return None

    def remove_remote(self):
        """移除一个远程配置"""
        remotes = self.get_remotes()
        if remotes is None: # Error occurred
            return
        if not remotes:
            QMessageBox.information(self, "信息", "没有可移除的远程配置。")
            return

        dialog = CustomGetItemDialog(self, "移除远程", "远程名称", remotes)
        if dialog.exec_():
            remote_to_delete, ok = dialog.get_result()
        else:
            remote_to_delete, ok = None, False
        if ok and remote_to_delete:
            config_dir = self.get_rclone_config_dir()
            config_file = os.path.join(config_dir, "rclone.conf")

            if not os.path.exists(config_file):
                self.config_output.append(f"错误: 配置文件 {config_file} 不存在。")
                return

            with open(config_file, 'r', encoding='utf-8') as f:
                config_content = f.read()

            new_config_content = self.remove_existing_remote(config_content, remote_to_delete)

            with open(config_file, 'w', encoding='utf-8') as f:
                f.write(new_config_content)

            self.config_output.append(f"远程 '{remote_to_delete}' 已被移除。")
            self.list_remotes() # Refresh the list.

    def get_rclone_config_dir(self) -> str:
        """获取rclone配置目录"""
        if sys.platform == "win32":
            return os.path.join(os.environ.get('APPDATA', ''), 'rclone')
        else:
            home = os.path.expanduser("~")
            return os.path.join(home, '.config', 'rclone')

    def remove_existing_remote(self, config_content: str, remote_name: str) -> str:
        """从配置中移除已存在的远程"""
        lines = config_content.split('\n')
        result_lines = []
        skip_section = False

        for line in lines:
            if line.strip().startswith('[') and line.strip().endswith(']'):
                section_name = line.strip()[1:-1]
                skip_section = (section_name == remote_name)

            if not skip_section:
                result_lines.append(line)

        return '\n'.join(result_lines)



class MountTab(QWidget):
    """挂载选项卡"""

    def __init__(self):
        super().__init__()
        self.rclone_path = ""
        self.load_default_mount_settings()
        self.init_ui()
        self.active_mounts = {}  # remote_name -> (worker, thread)
        self.remote_rows = {}    # remote_name -> row_index
        self.is_mounted = False

    def load_default_mount_settings(self):
        """加载默认挂载设置"""
        settings_file = Path(os.path.dirname(__file__)) / 'settings.json'
        self.default_mount_options = get_default_mount_options()
        try:
            if settings_file.exists():
                with open(settings_file, 'r') as f:
                    settings = json.load(f)
                    if 'default_mount_options' in settings:
                        self.default_mount_options.update(settings['default_mount_options'])
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error loading mount settings: {e}")

    def save_default_mount_settings(self):
        """保存默认挂载设置"""
        settings_file = Path(os.path.dirname(__file__)) / 'settings.json'
        settings = {}
        try:
            if settings_file.exists():
                with open(settings_file, 'r') as f:
                    settings = json.load(f)
            
            settings['default_mount_options'] = self.default_mount_options
            
            with open(settings_file, 'w') as f:
                json.dump(settings, f, indent=4)
        except IOError as e:
            print(f"Error saving mount settings: {e}")

    def open_default_settings(self):
        """打开默认参数设置对话框"""
        dialog = DefaultMountSettingsDialog(self.default_mount_options, self)
        if dialog.exec():
            self.default_mount_options = dialog.get_settings()
            self.save_default_mount_settings()

    def init_ui(self):
        layout = QVBoxLayout()

        self.mount_output = QTextEdit()
        self.mount_output.setReadOnly(True)
        self.mount_output.setFixedHeight(100)

        mount_group = QGroupBox("挂载配置")
        mount_layout = QVBoxLayout()

        self.remote_list = QComboBox()
        self.remote_list.setFixedHeight(30)
        self.remote_list.setFixedWidth(150)

        remote_refresh_btn = QPushButton("刷新")
        remote_refresh_btn.setFixedHeight(30)
        remote_refresh_btn.setFixedWidth(150)
        remote_refresh_btn.clicked.connect(self.populate_remotes)

        add_mount_btn = QPushButton("添加挂载")
        add_mount_btn.setFixedHeight(30)
        add_mount_btn.setFixedWidth(150)
        add_mount_btn.clicked.connect(self.add_to_mount_table)

        save_list_btn = QPushButton("保存列表")
        save_list_btn.setFixedHeight(30)
        save_list_btn.setFixedWidth(150)
        save_list_btn.clicked.connect(self.save_mount_list)

        load_list_btn = QPushButton("加载列表")
        load_list_btn.setFixedHeight(30)
        load_list_btn.setFixedWidth(150)
        load_list_btn.clicked.connect(self.load_mount_list)

        default_settings_btn = QPushButton("默认参数")
        default_settings_btn.setFixedHeight(30)
        default_settings_btn.setFixedWidth(150)
        default_settings_btn.clicked.connect(self.open_default_settings)

        clear_all_btn = QPushButton("清空挂载")
        clear_all_btn.setFixedHeight(30)
        clear_all_btn.setFixedWidth(150)
        clear_all_btn.clicked.connect(self.clear_all_mounts)

        self.mount_btn = QPushButton("开始挂载")
        self.mount_btn.setFixedHeight(30)
        self.mount_btn.setFixedWidth(150)
        self.mount_btn.clicked.connect(self.toggle_mount)

        # Row 1: 远程名称下拉, 刷新, 默认参数, 添加挂载
        row1_layout = QHBoxLayout()
        row1_layout.addWidget(self.remote_list)
        row1_layout.addStretch()
        row1_layout.addWidget(remote_refresh_btn)
        row1_layout.addStretch()
        row1_layout.addWidget(default_settings_btn)
        row1_layout.addStretch()
        row1_layout.addWidget(add_mount_btn)

        # Row 2: 保存列表, 加载列表, 清空列表, 开始挂载
        row2_layout = QHBoxLayout()
        row2_layout.addWidget(save_list_btn)
        row2_layout.addStretch()
        row2_layout.addWidget(load_list_btn)
        row2_layout.addStretch()
        row2_layout.addWidget(clear_all_btn)
        row2_layout.addStretch()
        row2_layout.addWidget(self.mount_btn)

        self.mount_table = QTableWidget()
        self.mount_table.setColumnCount(len(get_column_headers()))
        self.mount_table.setHorizontalHeaderLabels(get_column_headers())
        self.mount_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.mount_table.horizontalHeader().setFixedHeight(30) # Added this line
        self.mount_table.verticalHeader().setVisible(False)

        mount_layout.addLayout(row1_layout)
        mount_layout.addLayout(row2_layout)
        mount_layout.addWidget(self.mount_table)

        mount_group.setLayout(mount_layout)

        layout.addWidget(mount_group)
        layout.addWidget(QLabel("挂载日志"))
        layout.addWidget(self.mount_output)

        self.setLayout(layout)

    def set_rclone_path(self, path):
        self.rclone_path = path

    def populate_remotes(self):
        """填充远程名称列表"""
        self.remote_list.clear()
        try:
            if os.path.exists(self.rclone_path):
                creation_flags = 0
                if sys.platform == 'win32':
                    creation_flags = subprocess.CREATE_NO_WINDOW
                result = subprocess.run(
                    [self.rclone_path, 'listremotes'],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    encoding='utf-8',
                    errors='ignore',
                    creationflags=creation_flags
                )

                if result.returncode == 0 and result.stdout:
                    remotes = result.stdout.strip().split('\n')
                    remotes = [remote.strip().rstrip(':') for remote in remotes if remote.strip()]
                    for remote in remotes:
                        self.remote_list.addItem(remote)
                    self.mount_output.append("远程列表已刷新")
                else:
                    self.mount_output.append("获取远程列表失败: 无远程配置或命令错误")
            else:
                self.mount_output.append("获取远程列表失败: RClone可执行文件不存在")
        except Exception as e:
            self.mount_output.append(f"获取远程列表失败: {str(e)}")

    def add_to_mount_table(self):
        """将选中的远程添加到挂载表"""
        selected_remote = self.remote_list.currentText()
        if not selected_remote:
            QMessageBox.information(self, "提示", "请先选择远程名称")
            return

        # Check if remote already exists in the table
        if selected_remote in self.remote_rows:
            self.mount_output.append(f"远程 '{selected_remote}' 已在挂载表中")
            return

        row_count = self.mount_table.rowCount()
        self.mount_table.insertRow(row_count)
        self.remote_rows[selected_remote] = row_count

        selected_drive = get_next_available_drive(self.mount_table)
        populate_mount_table_row(self.mount_table, row_count, selected_remote, self.default_mount_options, self.remove_mount_row, selected_drive)
        self.auto_save_mount_list()

    def remove_mount_row(self):
        """移除挂载表中的行"""
        button = self.sender()
        for row in range(self.mount_table.rowCount()):
            if self.mount_table.cellWidget(row, 5) == button:
                remote_name = self.mount_table.item(row, 0).text()
                if remote_name in self.active_mounts:
                    reply = QMessageBox.question(self, "确认", f"远程 '{remote_name}' 正在挂载中，是否停止并移除？",
                                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                    if reply == QMessageBox.Yes:
                        self.stop_mount_for_remote(remote_name)
                        self.mount_table.removeRow(row)
                        del self.remote_rows[remote_name]
                        self.mount_output.append(f"已移除远程 '{remote_name}'")
                        self.auto_save_mount_list()
                    else:
                        return
                else:
                    self.mount_table.removeRow(row)
                    del self.remote_rows[remote_name]
                    self.mount_output.append(f"已移除远程 '{remote_name}'")
                    self.auto_save_mount_list()
                break

    def clear_all_mounts(self):
        """清空所有挂载配置"""
        if self.active_mounts:
            reply = QMessageBox.question(self, "确认", "是否停止所有挂载并清空列表？",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                for remote_name in list(self.active_mounts.keys()):
                    self.stop_mount_for_remote(remote_name)
                self.mount_table.setRowCount(0)
                self.remote_rows.clear()
                self.mount_output.append("已清空所有挂载配置")
                self.auto_save_mount_list()
        else:
            self.mount_table.setRowCount(0)
            self.remote_rows.clear()
            self.mount_output.append("已清空所有挂载配置")
            self.auto_save_mount_list()

    def auto_save_mount_list(self):
        """Automatically saves the mount list if a path is already configured."""
        main_window = self.window()
        
        file_path_to_save = None
        
        # Check if last_mount_list is set and its directory exists
        if hasattr(main_window, 'last_mount_list') and main_window.last_mount_list:
            potential_file_path = main_window.last_mount_list
            if os.path.isdir(os.path.dirname(potential_file_path)):
                file_path_to_save = potential_file_path

        if not file_path_to_save:
            # If no valid last_mount_list, default to a file in the current working directory
            if self.mount_table.rowCount() > 0:
                first_remote = self.mount_table.item(0, 0).text()
                suggested_filename = f"{first_remote}_mounts.json"
            else:
                suggested_filename = "mounts.json" # Fallback if no remotes
            app_data_dir = main_window.get_app_data_dir() # Access get_app_data_dir from main window
            os.makedirs(app_data_dir, exist_ok=True) # Ensure the directory exists
            file_path_to_save = os.path.join(app_data_dir, suggested_filename)
            main_window.set_last_mount_list(file_path_to_save) # Update last_mount_list for future auto-saves
        
        # Ensure the directory exists
        save_directory = os.path.dirname(file_path_to_save)
        try:
            os.makedirs(save_directory, exist_ok=True)
        except Exception as e:
            self.mount_output.append(f"创建保存目录失败: {str(e)}")
            return

        mounts_data = []
        for row in range(self.mount_table.rowCount()):
            mount_options = read_mount_options_from_row(self.mount_table, row, self.default_mount_options)
            mounts_data.append(mount_options)

        try:
            with open(file_path_to_save, 'w', encoding='utf-8') as f:
                json.dump(mounts_data, f, indent=4)
            self.mount_output.append(f"挂载列表已自动更新到: {os.path.basename(file_path_to_save)}")
        except Exception as e:
            self.mount_output.append(f"自动保存列表失败: {str(e)}")

    def save_mount_list(self):
        """Saves the current mount list to a user-selected JSON file."""
        if self.mount_table.rowCount() == 0:
            QMessageBox.information(self, "提示", "挂载列表为空，无需保存。")
            return

        first_remote = self.mount_table.item(0, 0).text()
        suggested_filename = f"{first_remote}_mounts.json"

        main_window = self.window()
        initial_dir = main_window.get_app_data_dir()
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存挂载列表", initial_dir, suggested_filename, "JSON文件 (*.json)"
        )
        if not file_path:
            return

        mounts_data = []
        for row in range(self.mount_table.rowCount()):
            mount_options = read_mount_options_from_row(self.mount_table, row, self.default_mount_options)
            mounts_data.append(mount_options)

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(mounts_data, f, indent=4)
            self.mount_output.append(f"挂载列表已保存到: {file_path}")
            main_window = self.window()
            if hasattr(main_window, 'set_last_mount_list'):
                main_window.set_last_mount_list(file_path)
        except Exception as e:
            self.mount_output.append(f"保存失败: {str(e)}")
            QMessageBox.information(self, "提示", f"无法保存挂载列表: {e}")

    def load_mount_list(self, file_path=None, auto_start=False):
        """Loads a mount list from a JSON file."""
        is_user_action = not auto_start
        
        if is_user_action:
            main_window = self.window()
            initial_dir = main_window.get_app_data_dir()
            file_path, _ = QFileDialog.getOpenFileName(
                self, "加载挂载列表", initial_dir, "JSON文件 (*.json)"
            )
        
        if not file_path or not os.path.exists(file_path):
            if is_user_action and file_path: # Only show error if user selected a non-existent file
                QMessageBox.information(self, "提示", f"文件不存在: {file_path}")
            elif not is_user_action:
                self.mount_output.append(f"自动加载失败: 未找到配置文件 {file_path}")
            return False

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                mounts_data = json.load(f)

            if is_user_action and self.mount_table.rowCount() > 0:
                reply = QMessageBox.question(self, "确认", "加载新列表将清空当前配置，是否继续？",
                                             QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                if reply == QMessageBox.No:
                    return False
            
            # Stop any active mounts before clearing the list
            if self.is_mounted:
                self.stop_mount()
            
            self.mount_table.setRowCount(0)
            self.remote_rows.clear()

            self.populate_remotes() # Refresh available remotes

            for mount_options in mounts_data:
                remote_name = mount_options.get('remote_name')
                if not remote_name:
                    self.mount_output.append("警告: 发现一个没有远程名称的挂载项，已跳过。")
                    continue
                
                if self.remote_list.findText(remote_name) == -1:
                    self.mount_output.append(f"警告: 远程 '{remote_name}' 不再存在，已跳过。")
                    continue

                if remote_name in self.remote_rows:
                    self.mount_output.append(f"警告: 远程 '{remote_name}' 在列表中重复，已跳过。")
                    continue

                row_count = self.mount_table.rowCount()
                self.mount_table.insertRow(row_count)
                self.remote_rows[remote_name] = row_count
                
                drive_letter = mount_options.get('mount_point', get_next_available_drive(self.mount_table))
                
                options_to_populate = self.default_mount_options.copy()
                options_to_populate.update(mount_options)

                populate_mount_table_row(self.mount_table, row_count, remote_name, options_to_populate, self.remove_mount_row, drive_letter)

            self.mount_output.append(f"挂载列表已从 {file_path} 加载。")
            
            main_window = self.window()
            if hasattr(main_window, 'set_last_mount_list'):
                main_window.set_last_mount_list(file_path)
            
            return True
        except Exception as e:
            self.mount_output.append(f"加载列表失败: {str(e)}")
            if is_user_action:
                QMessageBox.information(self, "提示", f"无法加载挂载列表: {e}")
            return False

    def stop_mount_for_remote(self, remote_name):
        """停止特定远程的挂载"""
        if remote_name in self.active_mounts:
            worker, thread = self.active_mounts[remote_name]
            # Get mount_point and options from the table
            mount_point = ""
            network_mode = False
            if remote_name in self.remote_rows:
                row = self.remote_rows[remote_name]
                mount_options = read_mount_options_from_row(self.mount_table, row, self.default_mount_options)
                mount_point = mount_options.get('mount_point', '')
                network_mode = mount_options.get('network_mode', False)

            worker.stop(mount_point, network_mode)
            thread.quit()
            thread.wait()
            del self.active_mounts[remote_name]
            self.mount_output.append(f"已停止挂载远程 '{remote_name}'")

    

    def toggle_mount(self):
        if not self.is_mounted:
            start_mount_all(self)
        else:
            self.stop_mount()

    

    def stop_mount(self):
        """停止挂载"""
        for remote_name, (worker, thread) in list(self.active_mounts.items()):
            # Get mount_point and options from the table
            mount_point = ""
            network_mode = False
            if remote_name in self.remote_rows:
                row = self.remote_rows[remote_name]
                mount_options = read_mount_options_from_row(self.mount_table, row, self.default_mount_options)
                mount_point = mount_options.get('mount_point', '')
                network_mode = mount_options.get('network_mode', False)

            worker.stop(mount_point, network_mode)
            thread.quit()
            thread.wait(5000)  # Wait up to 5 seconds for thread to finish
            if thread.isRunning():
                thread.terminate()
                thread.wait()
            self.active_mounts.pop(remote_name, None)

        self.is_mounted = False
        self.mount_btn.setText("开始挂载")
        self.mount_output.append("所有挂载已停止")

    def cleanup_thread(self, remote_name):
        """清理线程"""
        if remote_name in self.active_mounts:
            self.active_mounts.pop(remote_name, None)
            if not self.active_mounts:
                self.is_mounted = False
                self.mount_btn.setText("开始挂载")

    def validate_mount_inputs(self):
        """验证挂载输入"""
        if not self.rclone_path or not os.path.exists(self.rclone_path):
            QMessageBox.information(self, "提示", "请指定有效的RClone可执行文件路径")
            return False

        if self.mount_table.rowCount() == 0:
            return False

        for row in range(self.mount_table.rowCount()):
            mount_point_widget = self.mount_table.cellWidget(row, 1)
            if not self.mount_table.item(row, 0) or not (mount_point_widget and mount_point_widget.currentText()):
                QMessageBox.information(self, "提示", "请确保所有远程名称和挂载点已填写")
                return False

        return True

    def update_mount_output(self, text):
        """更新挂载输出"""
        self.mount_output.append(text)

    def update_mount_status(self, remote_name, status):
        """更新挂载状态"""
        if remote_name in self.remote_rows:
            row = self.remote_rows[remote_name]
            status_item = QTableWidgetItem(status)
            status_item.setFlags(status_item.flags() & ~Qt.ItemIsEditable)
            status_item.setTextAlignment(Qt.AlignCenter)
            if status == "挂载成功":
                status_item.setForeground(QColor("green"))
            elif status == "挂载失败":
                status_item.setForeground(QColor("red"))
            else:
                status_item.setForeground(QColor("black"))
            self.mount_table.setItem(row, 4, status_item)

    def handle_mount_error(self, error):
        """处理挂载错误"""
        self.mount_output.append(f"错误: {error}")



class SettingsTab(QWidget):
    """设置选项卡"""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        # Import autostart functions, handle if the module/dependencies are missing
        try:
            from autostart import set_autostart, is_autostart_enabled
            self.autostart_available = True
            self.set_autostart = set_autostart
            self.is_autostart_enabled = is_autostart_enabled
        except (ImportError, ModuleNotFoundError):
            self.autostart_available = False
            # Create dummy functions if autostart is not available
            self.set_autostart = lambda x: print("Autostart feature not available.")
            self.is_autostart_enabled = lambda: False
            print("Warning: 'autostart' module or its dependencies (e.g., pywin32) not found. Autostart feature disabled.")

        self.init_ui()
        
        # Initial UI state updates
        if self.autostart_available:
            self.update_autostart_status()
        self.update_tray_visibility_button_style()

    def init_ui(self):
        layout = QVBoxLayout()

        # --- Theme Settings ---
        theme_group = QGroupBox("主题")
        theme_layout = QHBoxLayout()

        self.system_theme_btn = QPushButton("跟随系统")
        self.system_theme_btn.setFixedSize(80, 30)
        self.light_theme_btn = QPushButton("浅色")
        self.light_theme_btn.setFixedSize(80, 30)
        self.dark_theme_btn = QPushButton("深色")
        self.dark_theme_btn.setFixedSize(80, 30)

        self.system_theme_btn.setObjectName("跟随系统")
        self.light_theme_btn.setObjectName("浅色")
        self.dark_theme_btn.setObjectName("深色")

        self.system_theme_btn.clicked.connect(self.on_theme_changed)
        self.light_theme_btn.clicked.connect(self.on_theme_changed)
        self.dark_theme_btn.clicked.connect(self.on_theme_changed)

        theme_layout.addWidget(self.system_theme_btn)
        theme_layout.addWidget(self.light_theme_btn)
        theme_layout.addWidget(self.dark_theme_btn)
        theme_layout.addStretch()
        
        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)

        # --- Tray Icon Settings ---
        tray_group = QGroupBox("托盘图标")
        tray_layout = QFormLayout()
        self.tray_visibility_button = QPushButton()
        self.tray_visibility_button.setFixedHeight(30)
        self.tray_visibility_button.setCheckable(True)
        self.tray_visibility_button.clicked.connect(self.toggle_tray_visibility)
        tray_layout.addRow("托盘图标", self.tray_visibility_button)
        tray_group.setLayout(tray_layout)
        layout.addWidget(tray_group)


        # --- Autostart Settings ---
        if self.autostart_available and sys.platform == "win32":
            autostart_group = QGroupBox("开机启动")
            autostart_layout = QFormLayout()
            self.autostart_button = QPushButton()
            self.autostart_button.setFixedHeight(30)
            self.autostart_button.setCheckable(True)
            self.autostart_button.clicked.connect(self.toggle_autostart)
            
            autostart_layout.addRow("开机启动", self.autostart_button)
            autostart_group.setLayout(autostart_layout)
            layout.addWidget(autostart_group)

        layout.addStretch()

        # Version and Author Information
        version_label = QLabel(f"版本: {QApplication.instance().applicationVersion()}")
        version_label.setStyleSheet("color: grey;")

        author_label = QLabel('<a href="https://github.com/FueTsui" style="color: grey; text-decoration:none;">FueTsui</a>')
        author_label.setOpenExternalLinks(True)
        
        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(version_label)
        bottom_layout.addStretch()
        bottom_layout.addWidget(author_label)
        
        layout.addLayout(bottom_layout)

        self.setLayout(layout)

    def on_theme_changed(self):
        sender = self.sender()
        if sender:
            theme_name = sender.objectName()
            self.parent.set_theme(theme_name)

    def update_theme_selection(self, theme_name):
        """Updates the theme buttons' styles to reflect the current theme."""
        buttons = {
            "跟随系统": self.system_theme_btn,
            "浅色": self.light_theme_btn,
            "深色": self.dark_theme_btn
        }

        selected_style = "QPushButton { background-color: #4CAF50; color: white; border: 1px solid #4CAF50; border-radius: 5px; }"
        default_style = "QPushButton { background-color: #f0f0f0; color: black; border: 1px solid #cccccc; border-radius: 5px; }"

        for name, button in buttons.items():
            if name == theme_name:
                button.setStyleSheet(selected_style)
            else:
                button.setStyleSheet(default_style)

    def toggle_tray_visibility(self):
        """Toggles the tray icon's visibility."""
        is_hidden = self.tray_visibility_button.isChecked()
        self.parent.tray_icon_hidden = is_hidden
        self.parent.save_settings()
        self.parent.update_tray_icon_visibility()
        self.update_tray_visibility_button_style()

    def update_tray_visibility_button_style(self):
        """Updates the button text and color based on the parent's state."""
        is_hidden = self.parent.tray_icon_hidden
        self.tray_visibility_button.setChecked(is_hidden)
        if is_hidden:
            self.tray_visibility_button.setText("隐藏")
        else:
            self.tray_visibility_button.setText("显示")

    def toggle_autostart(self):
        """Toggles the autostart setting when the button is clicked."""
        if not self.autostart_available:
            return
        enabled = self.autostart_button.isChecked()
        try:
            self.set_autostart(enabled)
            # Verify the change was successful
            QTimer.singleShot(200, self.update_autostart_status) # Use a timer to give registry time to update
        except Exception as e:
            QMessageBox.information(self, "提示", f"无法更新开机启动设置: {e}\n请尝试以管理员身份运行此程序。" )
            # Revert button state if setting failed
            self.update_autostart_status()

    def update_autostart_status(self):
        """Reads the system autostart state and updates the button."""
        if hasattr(self, 'autostart_button'):
            is_enabled = self.is_autostart_enabled()
            self.autostart_button.setChecked(is_enabled)
            self.update_autostart_button_style()

    def update_autostart_button_style(self):
        """Updates the button text and color based on its checked state."""
        if not hasattr(self, 'autostart_button'):
            return
            
        if self.autostart_button.isChecked():
            self.autostart_button.setText("开启")
        else:
            self.autostart_button.setText("关闭")

class RCloneGUI(QMainWindow):
    """RClone GUI主窗口"""
    def __init__(self):
        super().__init__()
        self.server = None
        self.settings_file = Path(self.get_app_data_dir()) / 'settings.json'
        self.rclone_path = os.path.abspath("./rclone.exe")
        self.tray_icon_hidden = False
        self.theme = "跟随系统"
        self.last_mount_list = None
        self.load_settings()

        # Capture the original system palette before any changes
        self.original_palette = QApplication.instance().palette()

        self.init_ui()
        self.init_tray_icon()
        
        # Apply theme on startup
        self.set_theme(self.theme, on_startup=True)

        # Automatically load and mount on startup
        self.auto_mount_on_startup()

    def init_ui(self):
        self.setWindowTitle("RcloneLink")
        self.setFixedSize(680, 540)

        # Center the window on the screen
        screen_geometry = QApplication.primaryScreen().geometry()
        window_geometry = self.frameGeometry()
        window_geometry.moveCenter(screen_geometry.center())
        self.move(window_geometry.topLeft())

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        tab_widget = QTabWidget()

        self.config_tab = ConfigTab()
        tab_widget.addTab(self.config_tab, "配置")

        self.mount_tab = MountTab()
        tab_widget.addTab(self.mount_tab, "挂载")

        self.settings_tab = SettingsTab(self)
        tab_widget.addTab(self.settings_tab, "设置")

        # Connect signals for rclone path synchronization
        self.config_tab.rclone_path_changed.connect(self.on_rclone_path_changed)

        # Set initial rclone path from loaded settings
        self.config_tab.rclone_path_edit.setText(self.rclone_path)
        self.mount_tab.set_rclone_path(self.rclone_path)
        self.mount_tab.populate_remotes()

        layout = QVBoxLayout()
        layout.addWidget(tab_widget)
        central_widget.setLayout(layout)

    def set_theme(self, theme, on_startup=False):
        """Sets the application theme using palettes for consistency with Fusion style."""
        if not on_startup:
            self.theme = theme
            self.save_settings()

        self.settings_tab.update_theme_selection(theme)
        
        app = QApplication.instance()
        
        # Clear any previous custom stylesheet to let the QStyle and QPalette take full control
        app.setStyleSheet("")

        if theme == "深色":
            dark_palette = QPalette()
            dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
            dark_palette.setColor(QPalette.WindowText, Qt.white)
            dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
            dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
            dark_palette.setColor(QPalette.ToolTipText, Qt.white)
            dark_palette.setColor(QPalette.Text, Qt.white)
            dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
            dark_palette.setColor(QPalette.ButtonText, Qt.white)
            dark_palette.setColor(QPalette.BrightText, Qt.red)
            dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
            dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            dark_palette.setColor(QPalette.HighlightedText, Qt.black)
            app.setPalette(dark_palette)
        elif theme == "浅色":
            # Create a new standard light palette to ensure a consistent light theme
            # based on the Fusion style, rather than the original system one.
            light_palette = QPalette()
            app.setPalette(light_palette)
        else: # "跟随系统"
            # Restore the palette captured at startup, which reflects the OS's colors
            app.setPalette(self.original_palette)

    def on_rclone_path_changed(self, path):
        self.rclone_path = path
        self.mount_tab.set_rclone_path(path)
        self.save_settings()

    def init_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        
        tray_menu = QMenu()
        show_action = QAction("显示窗口", self)
        show_action.triggered.connect(self.show_normal)
        tray_menu.addAction(show_action)

        quit_action = QAction("退出", self)
        quit_action.triggered.connect(self.quit_application)
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_icon_activated)
        
        # Apply visibility from settings
        self.update_tray_icon_visibility()

    def get_app_data_dir(self) -> str:
        """获取应用程序数据目录"""
        if sys.platform == "win32":
            return os.path.join(os.environ.get('APPDATA', ''), 'RcloneLink')
        else:
            home = os.path.expanduser("~")
            return os.path.join(home, '.local', 'share', 'RcloneLink') # Or ~/.config/RcloneLink

    def show_normal(self):
        self.show()
        self.activateWindow()

    def on_tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_normal()

    def update_tray_icon_visibility(self):
        # Shows or hides the tray icon based on the setting.
        if self.tray_icon_hidden:
            self.tray_icon.hide()
        else:
            self.tray_icon.show()

    def load_settings(self):
        try:
            if self.settings_file.exists():
                with open(self.settings_file, 'r') as f:
                    settings = json.load(f)
                    self.rclone_path = os.path.abspath(settings.get('rclone_path', './rclone.exe'))
                    self.tray_icon_hidden = settings.get('tray_icon_hidden', False)
                    self.theme = settings.get('theme', '跟随系统')
                    self.last_mount_list = settings.get('last_mount_list')
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error loading settings: {e}")

    def save_settings(self):
        try:
            # First, read existing settings to not overwrite them
            if self.settings_file.exists():
                with open(self.settings_file, 'r') as f:
                    settings = json.load(f)
            else:
                settings = {}
            
            settings['rclone_path'] = self.rclone_path
            settings['tray_icon_hidden'] = self.tray_icon_hidden
            settings['theme'] = self.theme
            settings['last_mount_list'] = self.last_mount_list
            
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=4)
        except IOError as e:
            print(f"Error saving settings: {e}")

    def set_last_mount_list(self, file_path):
        """Stores the path of the last used mount list and saves it."""
        if self.last_mount_list != file_path:
            self.last_mount_list = file_path
            self.save_settings()

    def auto_mount_on_startup(self):
        """If a previous mount list is remembered, load and start it."""
        if self.last_mount_list and os.path.exists(self.last_mount_list):
            # Use a timer to ensure the main window is fully shown and ready
            QTimer.singleShot(200, self.perform_auto_mount)

    def perform_auto_mount(self):
        """Loads the list and starts mounting."""
        self.mount_tab.mount_output.append(f"自动加载上次使用的挂载列表: {self.last_mount_list}")
        if self.mount_tab.load_mount_list(file_path=self.last_mount_list, auto_start=True):
            self.mount_tab.mount_output.append("列表加载成功，自动开始挂载...")
            self.mount_tab.toggle_mount()
        else:
            self.mount_tab.mount_output.append("自动挂载失败: 无法加载列表。")

    def quit_application(self):
        # Stops all tasks and quits the application.
        self.mount_tab.stop_mount()
        self.tray_icon.hide()
        QApplication.instance().quit()

    def handle_new_connection(self):
        socket = self.server.nextPendingConnection()
        if socket:
            socket.waitForReadyRead(500)
            socket.disconnectFromServer()
            self.show_normal()

    def closeEvent(self, event):
        # Closing the window always minimizes it to let it run in the background.
        event.ignore()
        self.hide()


def check_winfsp_installed():
    """Checks if WinFsp is installed by checking the Windows Registry and falling back to filesystem."""
    if sys.platform != "win32":
        return True  # Not a windows system, skip check

    # List of possible registry locations to check
    # (hive, key, access_flags)
    # The access flag forces looking at the 64-bit registry view from a 32-bit app
    registry_checks = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WinFsp", winreg.KEY_READ),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WinFsp", winreg.KEY_READ | winreg.KEY_WOW64_64KEY),
    ]

    for hive, key_path, access in registry_checks:
        try:
            with winreg.OpenKey(hive, key_path, 0, access) as key:
                return True  # Found it
        except FileNotFoundError:
            continue  # Not here, try next
        except Exception as e:
            print(f"Registry check error: {e}")  # Log other errors but continue
            continue

    # If registry checks fail, fallback to file system check
    fs_checks = [
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "WinFsp"),
        os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "WinFsp"),
    ]
    for path in fs_checks:
        if os.path.isdir(path):
            return True

    return False

def show_winfsp_install_prompt():
    """Shows a dialog to prompt the user to install WinFsp."""
    msg_box = QMessageBox()
    icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')
    if os.path.exists(icon_path):
        msg_box.setWindowIcon(QIcon(icon_path))
    msg_box.setIcon(QMessageBox.Information)
    msg_box.setWindowTitle("缺少依赖")
    msg_box.setText("RcloneLink 需要 WinFsp 才能挂载磁盘。\n检测到您的系统尚未安装 WinFsp。")
    msg_box.setInformativeText("从本地直接安装，或访问官网下载。")

    install_button = msg_box.addButton("本地安装", QMessageBox.ActionRole)
    website_button = msg_box.addButton("访问官网", QMessageBox.ActionRole)
    cancel_button = msg_box.addButton("退出", QMessageBox.RejectRole)

    msg_box.exec()

    if msg_box.clickedButton() == install_button:
        installer_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'winfsp-2.1.25156.msi')
        if os.path.exists(installer_path):
            try:
                # Use ShellExecuteW to run the installer with admin rights
                ctypes.windll.shell32.ShellExecuteW(None, "runas", "msiexec.exe", f'/i "{installer_path}"', None, 1)
            except Exception as e:
                QMessageBox.information(None, "提示", f"无法启动 WinFsp 安装程序: {e}\n请尝试手动右键以管理员身份运行 winfsp-2.1.25156.msi。")
        else:
            QMessageBox.information(None, "提示", f"未找到安装文件: {installer_path}")
        return False  # Exit app
    elif msg_box.clickedButton() == website_button:
        webbrowser.open("https://winfsp.dev/rel/")
        return False  # Exit app
    else:  # Cancel or closed
        return False  # Exit app


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    server_name = "RcloneLink_App_Instance"
    socket = QLocalSocket()
    socket.connectToServer(server_name)

    if socket.waitForConnected(500):
        # Another instance is running, send a signal and exit
        socket.write(b'show')
        socket.waitForBytesWritten(500)
        socket.disconnectFromServer()
        sys.exit(0)
    else:
        # This is the first instance, create a server
        server = QLocalServer()
        server.removeServer(server_name)  # Clean up any stale lock
        if not server.listen(server_name):
            QMessageBox.information(None, "提示", f"无法启动本地服务: {server.errorString()}")
            sys.exit(1)

    if not check_winfsp_installed():
        if not show_winfsp_install_prompt():
            sys.exit(0)

    app.setApplicationName("RcloneLink")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Rclone Tools")

    icon_path = os.path.join(os.path.dirname(__file__), 'icon.png')
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    else:
        print("警告: 应用程序图标文件 icon.png 不存在。" )

    window = RCloneGUI()
    
    # Attach the server to the window
    window.server = server
    server.newConnection.connect(window.handle_new_connection)

    if "--minimized" in sys.argv:
        window.hide()
    else:
        window.show()

    sys.exit(app.exec())



if __name__ == "__main__":
    main()