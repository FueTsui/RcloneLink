#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import subprocess
from typing import Dict
from PySide6.QtWidgets import (
    QTableWidgetItem, QComboBox, QLineEdit, QPushButton
)
from PySide6.QtCore import Qt, QThread, QObject, Signal, QTimer, QProcess

# 表格列定义
COLUMN_HEADERS = [
    "远程名称", "挂载点", "磁盘空间", "文件权限", "状态", "操作"
]

class RCloneMountWorker(QObject):
    """RClone挂载工作线程"""
    output_signal = Signal(str)
    status_signal = Signal(str, str)  # remote_name, status
    error_signal = Signal(str)

    def __init__(self, rclone_path: str):
        super().__init__()
        self.rclone_path = rclone_path
        self.process = None
        self.is_running = False
        self.remote_name = None

    def mount(self, remote_name: str, mount_point: str, options: Dict):
        """挂载远程存储"""
        self.remote_name = remote_name
        try:
            cmd = build_mount_command(self.rclone_path, remote_name, mount_point, options)

            self.output_signal.emit(f"执行命令: {' '.join(cmd)}")

            self.process = QProcess(self)  # Ensure QProcess is a child of the worker
            self.process.setProgram(self.rclone_path)
            self.process.setArguments(cmd[1:])
            self.process.setProcessChannelMode(QProcess.MergedChannels)

            self.process.readyReadStandardOutput.connect(self.handle_output)
            self.process.readyReadStandardError.connect(self.handle_error)
            self.process.finished.connect(self.handle_finished)
            self.process.errorOccurred.connect(self.handle_process_error)

            self.process.start()
            self.is_running = True
            self.status_signal.emit(self.remote_name, "正在挂载")

            self.verify_timer = QTimer(self)  # Ensure QTimer is a child of the worker
            self.verify_timer.setSingleShot(True)
            self.verify_timer.timeout.connect(lambda: self.verify_mount(mount_point))
            self.verify_timer.start(5000)

        except Exception as e:
            self.error_signal.emit(f"挂载错误: {str(e)}")
            self.status_signal.emit(self.remote_name, "挂载失败")
            self.is_running = False

    def handle_output(self):
        """处理标准输出"""
        if self.process:
            output = self.process.readAllStandardOutput().data().decode('utf-8', errors='ignore').strip()
            if output:
                self.output_signal.emit(output)

    def handle_error(self):
        """处理错误输出"""
        if self.process:
            error = self.process.readAllStandardError().data().decode('utf-8', errors='ignore').strip()
            if error:
                self.error_signal.emit(error)

    def handle_finished(self, exit_code, exit_status):
        """处理进程结束"""
        self.is_running = False
        if exit_code == 0 and exit_status == QProcess.NormalExit:
            self.status_signal.emit(self.remote_name, "挂载已停止")
        else:
            self.status_signal.emit(self.remote_name, "挂载失败")
            self.error_signal.emit(f"挂载进程异常退出，退出码: {exit_code}")

        self.process = None
        if hasattr(self, 'verify_timer') and self.verify_timer:
            self.verify_timer.stop()
            self.verify_timer.deleteLater()

    def handle_process_error(self, error):
        """处理 QProcess 错误"""
        error_messages = {
            QProcess.FailedToStart: "挂载进程无法启动，可能 rclone 可执行文件无效",
            QProcess.Crashed: "挂载进程崩溃",
            QProcess.Timedout: "挂载进程超时",
            QProcess.WriteError: "写入挂载进程失败",
            QProcess.ReadError: "读取挂载进程输出失败",
            QProcess.UnknownError: "发生未知错误"
        }
        self.error_signal.emit(f"挂载错误: {error_messages.get(error, '未知错误')}")
        self.status_signal.emit(self.remote_name, "挂载失败")
        self.is_running = False
        self.process = None
        if hasattr(self, 'verify_timer') and self.verify_timer:
            self.verify_timer.stop()
            self.verify_timer.deleteLater()

    def verify_mount(self, mount_point: str):
        """验证挂载是否成功"""
        try:
            if sys.platform == "win32":
                import win32api
                drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
                drives = [d.rstrip('\\') for d in drives]
                if mount_point in drives:
                    self.status_signal.emit(self.remote_name, "挂载成功")
                    self.output_signal.emit(f"挂载点 {mount_point} 已成功挂载")
                else:
                    self.error_signal.emit(f"挂载失败: 挂载点 {mount_point} 未出现在驱动器列表中")
                    self.status_signal.emit(self.remote_name, "挂载失败")
                    self.stop()
            else:
                if os.path.exists(mount_point) and os.path.isdir(mount_point):
                    try:
                        subprocess.run([self.rclone_path, 'ls', f'{mount_point}/'], 
                                     capture_output=True, text=True, timeout=10)
                        self.status_signal.emit(self.remote_name, "挂载成功")
                        self.output_signal.emit(f"挂载点 {mount_point} 已成功挂载")
                    except subprocess.TimeoutExpired:
                        self.error_signal.emit(f"挂载失败: 无法访问挂载点 {mount_point}")
                        self.status_signal.emit(self.remote_name, "挂载失败")
                        self.stop()
                    except Exception as e:
                        self.error_signal.emit(f"挂载验证失败: {str(e)}")
                        self.status_signal.emit(self.remote_name, "挂载失败")
                        self.stop()
                else:
                    self.error_signal.emit(f"挂载失败: 挂载点 {mount_point} 不存在")
                    self.status_signal.emit(self.remote_name, "挂载失败")
                    self.stop()
        except Exception as e:
            self.error_signal.emit(f"挂载验证出错: {str(e)}")
            self.status_signal.emit(self.remote_name, "挂载失败")
            self.stop()

    def stop(self, mount_point: str, network_mode: bool = False):
        """停止挂载"""
        self.is_running = False
        if self.process:
            try:
                # Attempt to unmount using rclone rc command first
                if sys.platform == "win32":
                    # For Windows, use 'net use' to delete the network drive mapping
                    # This is more reliable for network mode mounts
                    unmount_cmd = ["net", "use", mount_point, "/delete"]
                    self.output_signal.emit(f"执行卸载命令: {' '.join(unmount_cmd)}")
                    subprocess.run(unmount_cmd, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    # For other OS, use rclone rc vfs/unmount
                    unmount_cmd = [self.rclone_path, "rc", "vfs/unmount", f"mountPoint={mount_point}"]
                    self.output_signal.emit(f"执行卸载命令: {' '.join(unmount_cmd)}")
                    subprocess.run(unmount_cmd, capture_output=True, text=True, timeout=10, encoding='utf-8', errors='ignore')

                self.process.terminate()
                self.process.waitForFinished(3000)
                if self.process.state() != QProcess.NotRunning:
                    self.process.kill()
                    self.output_signal.emit("强制终止挂载进程")
            except Exception as e:
                self.error_signal.emit(f"停止挂载失败: {str(e)}")
            finally:
                self.process = None
        self.status_signal.emit(self.remote_name, "已停止挂载")
        if hasattr(self, 'verify_timer') and self.verify_timer:
            self.verify_timer.stop()
            self.verify_timer.deleteLater()
        
        # Restart explorer.exe if network_mode is enabled on Windows
        if sys.platform == "win32" and network_mode:
            try:
                self.output_signal.emit("重启 explorer.exe...")
                subprocess.run(["taskkill", "/f", "/im", "explorer.exe"], creationflags=subprocess.CREATE_NO_WINDOW)
                subprocess.Popen("explorer.exe", creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
                self.output_signal.emit("explorer.exe 已重启。")
            except Exception as e:
                self.error_signal.emit(f"重启 explorer.exe 失败: {str(e)}")

def get_column_headers():
    """返回挂载表格的列标题"""
    return COLUMN_HEADERS

def get_default_mount_options():
    """返回挂载参数的默认值"""
    return {
        # 基本参数
        "cache_dir": os.path.join(os.environ.get('APPDATA', ''), 'RcloneLink', 'cache'),
        "log_level": "INFO",
        "network_mode": False,
        "no_check_certificate": True,
        "async_read": True,
        "ignore_case": True,
        "progress": True,
        "links": True,

        # 缓存优化
        "vfs_cache_mode": "full",
        "vfs_cache_max_size": "20G",
        "vfs_cache_max_age": "1h",
        "vfs_cache_poll_interval": "10s",
        "dir_cache_time": "1m",

        # 读写性能
        "vfs_read_ahead": "512M",
        "vfs_read_chunk_size": "128M",
        "vfs_read_chunk_size_limit": "2G",
        "buffer_size": "128M",
        "transfers": "8",
        "multi_thread_streams": "12",

        # 超时与重试
        "timeout": "1m",
        "contimeout": "15s",
        "retries": "5",
        "retries_sleep": "5s",
        
        # Others from UI
        "vfs_disk_space_total_size": "8T",
        "file_perms": "0777",
    }

def get_available_drives():
    """获取可用的驱动器号 (仅限Windows)"""
    if sys.platform == "win32":
        try:
            import win32api
            used_drives = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
            used_drives = [d.rstrip('\\') for d in used_drives]
            all_drives = [f"{chr(i)}:" for i in range(ord('A'), ord('Z') + 1)]
            return [d for d in all_drives if d not in used_drives]
        except ImportError:
            return []
    return []

def get_next_available_drive(table_widget):
    """获取下一个可用的驱动器号，从Z盘开始向前查找"""
    if sys.platform != "win32":
        return "/mnt/remote"

    used_drives = set()
    # 1. 获取系统已占用的驱动器号
    try:
        import win32api
        drive_strings = win32api.GetLogicalDriveStrings().split('\x00')[:-1]
        for d in drive_strings:
            used_drives.add(d.rstrip('\\'))
    except ImportError:
        pass  # 如果没有pywin32，则跳过

    # 2. 获取表格中已分配的驱动器号
    if table_widget:
        for row in range(table_widget.rowCount()):
            combo_box = table_widget.cellWidget(row, 1)
            if combo_box:
                used_drives.add(combo_box.currentText())

    # 3. 从 Z 到 C 查找未被占用的驱动器号
    for i in range(ord('Z'), ord('B'), -1):
        drive = f"{chr(i)}:"
        if drive not in used_drives:
            return drive
            
    # 4. 如果C-Z都被占用，尝试A
    if "A:" not in used_drives:
        return "A:"

    return "" # 如果所有盘符都被占用

def populate_mount_table_row(table, row, remote_name, defaults, remove_callback, selected_drive):
    """
    在挂载表格中填充一行新的挂载配置
    """
    # 0. 远程名称
    remote_item = QTableWidgetItem(remote_name)
    remote_item.setFlags(remote_item.flags() & ~Qt.ItemIsEditable)
    remote_item.setTextAlignment(Qt.AlignCenter)
    table.setItem(row, 0, remote_item)

    # 1. 挂载点
    mount_point_combo = QComboBox()
    available_drives = get_available_drives()
    
    # 确保建议的驱动器号在列表中
    if selected_drive and selected_drive not in available_drives:
        # 如果建议的驱动器已被系统占用，则添加到列表顶部让用户知晓
        all_items = [selected_drive] + available_drives
    else:
        all_items = available_drives

    if all_items:
        mount_point_combo.addItems(all_items)
    
    if selected_drive:
        mount_point_combo.setCurrentText(selected_drive)
    
    mount_point_combo.setEditable(True)
    mount_point_combo.lineEdit().setAlignment(Qt.AlignCenter)
    mount_point_combo.lineEdit().setReadOnly(True)
    table.setCellWidget(row, 1, mount_point_combo)


    # 2. 磁盘空间
    disk_space_edit = QLineEdit(defaults.get("vfs_disk_space_total_size", "8T"))
    disk_space_edit.setAlignment(Qt.AlignCenter)
    table.setCellWidget(row, 2, disk_space_edit)

    # 3. 文件权限
    file_perms_combo = QComboBox()
    file_perms_combo.addItems([
        "0777", "0755", "0744", "0644", "0700", "0600"
    ])
    file_perms_combo.setCurrentText(defaults.get("file_perms", "0777"))
    file_perms_combo.setEditable(True)
    file_perms_combo.lineEdit().setAlignment(Qt.AlignCenter)
    file_perms_combo.lineEdit().setReadOnly(True)
    table.setCellWidget(row, 3, file_perms_combo)

    # 4. 状态
    status_item = QTableWidgetItem("未挂载")
    status_item.setFlags(status_item.flags() & ~Qt.ItemIsEditable)
    status_item.setTextAlignment(Qt.AlignCenter)
    table.setItem(row, 4, status_item)

    # 5. 操作
    remove_btn = QPushButton("移除")
    remove_btn.clicked.connect(remove_callback)
    table.setCellWidget(row, 5, remove_btn)

def read_mount_options_from_row(table, row, defaults):
    """从表格行中读取挂载参数"""
    options = defaults.copy()
    options.update({
        'remote_name': table.item(row, 0).text(),
        'mount_point': table.cellWidget(row, 1).currentText(),
        'vfs_disk_space_total_size': table.cellWidget(row, 2).text(),
        'file_perms': table.cellWidget(row, 3).currentText(),
    })
    return options

def build_mount_command(rclone_path, remote_name, mount_point, options):
    """构建rclone mount命令"""
    cmd = [rclone_path, 'mount', f'{remote_name}:/', mount_point]
    
    param_map = {
        "vfs_cache_mode": "--vfs-cache-mode",
        "vfs_read_ahead": "--vfs-read-ahead",
        "buffer_size": "--buffer-size",
        "cache_dir": "--cache-dir",
        "log_level": "--log-level",
        "file_perms": "--file-perms",
        "dir_cache_time": "--dir-cache-time",
        "vfs_cache_max_age": "--vfs-cache-max-age",
        "vfs_cache_poll_interval": "--vfs-cache-poll-interval",
        "vfs_cache_max_size": "--vfs-cache-max-size",
        "vfs_disk_space_total_size": "--vfs-disk-space-total-size",
        "vfs_read_chunk_size": "--vfs-read-chunk-size",
        "vfs_read_chunk_size_limit": "--vfs-read-chunk-size-limit",
        "transfers": "--transfers",
        "multi_thread_streams": "--multi-thread-streams",
        "timeout": "--timeout",
        "contimeout": "--contimeout",
        "retries": "--retries",
        "retries_sleep": "--retries-sleep",
    }

    for key, flag in param_map.items():
        if options.get(key):
            cmd.extend([flag, str(options[key])])

    flag_map = {
        "progress": "--progress",
        "no_check_certificate": "--no-check-certificate",
        "links": "--links",
        "network_mode": "--network-mode",
        "async_read": "--async-read",
        "ignore_case": "--ignore-case",
    }

    for key, flag in flag_map.items():
        if options.get(key):
            cmd.append(flag)

    if sys.platform == "win32":
        cmd.append("--no-console")
            
    return cmd

def start_mount_all(mount_tab):
    """开始全部挂载"""
    if not mount_tab.validate_mount_inputs():
        return

    for row in range(mount_tab.mount_table.rowCount()):
        options = read_mount_options_from_row(mount_tab.mount_table, row, mount_tab.default_mount_options)
        remote_name = options.pop('remote_name')
        mount_point = options.pop('mount_point')

        if remote_name in mount_tab.active_mounts:
            mount_tab.mount_output.append(f"警告: 远程 '{remote_name}' 已在挂载")
            continue

        thread = QThread()
        worker = RCloneMountWorker(mount_tab.rclone_path)
        worker.moveToThread(thread)

        worker.output_signal.connect(mount_tab.update_mount_output)
        worker.status_signal.connect(mount_tab.update_mount_status)
        worker.error_signal.connect(mount_tab.handle_mount_error)

        thread.started.connect(
            lambda w=worker, r=remote_name, m=mount_point, o=options: w.mount(r, m, o)
        )
        thread.finished.connect(lambda r=remote_name: mount_tab.cleanup_thread(r))

        thread.start()
        mount_tab.active_mounts[remote_name] = (worker, thread)

    if mount_tab.active_mounts:
        mount_tab.is_mounted = True
        mount_tab.mount_btn.setText("停止挂载")
        mount_tab.mount_output.append("开始挂载所选远程存储...")
