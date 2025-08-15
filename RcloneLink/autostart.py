# autostart.py
import sys
import os
import winreg

APP_NAME = "RClone GUI"

def get_script_path():
    """Get the absolute path to the main script (rclone_gui.py)"""
    # When running as a script, sys.argv[0] is the script file.
    # When running as a frozen exe (e.g., with PyInstaller), sys.argv[0] is the exe.
    return os.path.abspath(sys.argv[0])

def get_pythonw_path():
    """Finds the path to pythonw.exe, falling back to python.exe"""
    if hasattr(sys, 'frozen'): # Check if running as a frozen exe
        return None
    python_exe = sys.executable
    pythonw_exe = python_exe.replace("python.exe", "pythonw.exe")
    if os.path.exists(pythonw_exe):
        return pythonw_exe
    return python_exe

def set_autostart(enable: bool):
    """
    Enables or disables autostart for the application on Windows.
    :param enable: True to enable, False to disable.
    """
    if sys.platform != "win32":
        print("Autostart is only supported on Windows.")
        return

    registry_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    
    command = ""
    if hasattr(sys, 'frozen'):
        # The application is a frozen executable
        command = f'"{get_script_path()}" --minimized'
    else:
        # The application is a Python script
        python_path = get_pythonw_path()
        script_path = get_script_path()
        if python_path:
            command = f'"{python_path}" "{script_path}" --minimized'
        else: # Should not happen if not frozen
             command = f'"{script_path}" --minimized'

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_WRITE)
        if enable:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, command)
        else:
            winreg.DeleteValue(key, APP_NAME)
        winreg.CloseKey(key)
    except FileNotFoundError:
        # This can happen if the value doesn't exist when trying to delete.
        pass
    except Exception as e:
        print(f"Failed to set autostart: {e}")

def is_autostart_enabled() -> bool:
    """
    Checks if autostart is currently enabled for the application on Windows.
    :return: True if enabled, False otherwise.
    """
    if sys.platform != "win32":
        return False

    registry_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_READ)
        winreg.QueryValueEx(key, APP_NAME)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False
