# RcloneLink

RcloneLink 是一个用户友好的图形界面 (GUI) 工具，主要为 Windows 用户设计，用于管理 Rclone WebDAV 挂载。它简化了配置 WebDAV 远程和将其挂载为本地驱动器的过程，并提供了各种 Rclone 选项以优化性能和缓存。

## 功能

*   **Rclone 路径配置**：轻松设置 Rclone 可执行文件的路径。
*   **WebDAV 远程管理**：添加、列出和删除 WebDAV 远程，支持密码加密。
*   **挂载管理**：
    *   将 WebDAV 远程挂载为本地驱动器（例如，Windows 上的 `X:` 驱动器）。
    *   配置各种 Rclone 挂载选项，包括 VFS 缓存设置、缓冲区大小、预读、日志级别和超时。
    *   保存和加载挂载配置，方便重复使用。
    *   启动和停止单个或所有已配置的挂载。
*   **系统集成**：
    *   最小化到系统托盘，在后台运行。
    *   可选择隐藏托盘图标。
    *   Windows 开机自启动（最小化启动）。
*   **主题**：可在系统默认、浅色和深色主题之间选择。
*   **WinFsp 检查**：自动检查 WinFsp 安装情况（Windows 上挂载所需），如果未找到则提供指导。

## 核心及依赖

RcloneLink 使用Rclone及WinFsp，默认内置也可以自行安装：

1.  **Rclone**：从 Rclone 官方网站 ([https://rclone.org/downloads/](https://rclone.org/downloads/)) 下载最新的 Rclone 可执行文件。将 `rclone.exe` 放在 RcloneLink 所在的目录，或在应用程序中指定其路径。
2.  **WinFsp**：这是一个 Windows 文件系统驱动程序，对于将云存储挂载为本地驱动器至关重要。如果未检测到 WinFsp，RcloneLink 将提示您安装。您也可以从 WinFsp 官方网站 ([https://winfsp.dev/rel/](https://winfsp.dev/rel/)) 下载。

**使用预构建的可执行文件 (Windows)**：

从 [发布页面](https://github.com/FueTsui/RcloneLink/releases/tag/v1.0.0) 下载最新的 `RcloneLink_Setup_X.X.X.exe` 并运行安装程序。这将安装 RcloneLink 及其依赖项。

## 使用方法

1.  **启动 RcloneLink**。
2.  **配置**：
    *   在“配置”选项卡中，确保 `rclone.exe` 的路径已正确设置。如果 `rclone.exe` 与 RcloneLink 在同一目录中，它应该会自动检测到。
    *   在“配置”选项卡中，输入您的 WebDAV 远程详细信息（名称、URL、用户名、密码、供应商），然后单击“添加配置”。
3.  **挂载**：
    *   导航到“挂载”选项卡。
    *   单击“刷新”以将已配置的远程加载到下拉列表中。
    *   选择一个远程，然后单击“添加挂载”将其添加到挂载表中。
    *   对于每个挂载，您可以通过单击“默认参数”来自定义挂载点（驱动器号）、磁盘空间、文件权限和高级 Rclone 选项。
    *   单击“保存列表”以保存您当前的挂载配置，或单击“加载列表”以加载以前保存的列表。
    *   单击“开始挂载”以挂载所有已配置的远程。按钮将变为“停止挂载”以卸载它们。
4.  **设置**：在“设置”选项卡中，您可以：
    *   更改应用程序主题。
    *   控制系统托盘图标的可见性。
    *   启用或禁用 Windows 开机自启动。

## 从源代码构建

要从源代码构建 RcloneLink，您需要 Python 3 和 `PySide6`、`pywin32`（用于开机自启动）以及 `PyInstaller`。

```bash
pip install PySide6 pywin32 pyinstaller
python -m PyInstaller RcloneLink.spec
```

这将在 `dist` 目录中生成可执行文件。

## 致谢
*   [Rclone](https://rclone.org/): 一个用于管理云存储文件的命令行程序.
*   [WinFsp](https://winfsp.dev/): 一款Windows文件系统依赖。


## 许可证

本项目采用 MIT 许可证 - 详情请参阅 LICENSE 文件。
