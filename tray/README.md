# VigilServeTray

VigilServe 服务端守护程序，常驻 Windows 系统托盘，提供可视化的服务控制面板。

## 功能

- 启动后隐藏在系统托盘，使用 VigilServe logo 作为托盘图标。
- 右键托盘图标菜单：
  - 打开 Web 控制台
  - 打开控制面板
  - 开机自启
  - 退出
- 控制面板功能：
  - 实时显示后端 API、前端静态、本地 Agent 的运行状态。
  - 对每个服务执行启动 / 停止 / 重启操作。
  - 自定义后端、前端、Agent 服务端口，配置保存至 `%APPDATA%\VigilServe\tray-config.json`。
  - 端口修改后重启对应服务即可生效。
- 每 1.5 秒自动刷新控制面板状态，托盘 tooltip 每 3 秒刷新。

## 管理的服务

| 服务 | 说明 | 数据库 |
|------|------|--------|
| 后端 API 服务 | FastAPI + uvicorn，提供 REST API 和 WebSocket 终端代理 | SQLite (backend/monitor.db) |
| 前端静态服务 | Vite 构建的静态页面 | - |
| 本地 Agent 服务 | 远程服务器监控 Agent | - |

## 运行方式

### 源码运行

```powershell
cd tray
python tray_app.py
```

### 打包为 EXE

托盘程序需要 **自带 tkinter 的 Python**（不含 tkinter 的发行版打出来的 exe 会
退化成网页版配置窗口），建议在独立 venv 里装依赖：

```powershell
python -m venv .venv-tray
.venv-tray\Scripts\pip.exe install -r requirements.txt pyinstaller
.venv-tray\Scripts\pyinstaller.exe --clean VigilServeTray.spec
```

打包完成后，`dist/VigilServeTray.exe` 可直接双击运行。

## 注意事项

- 首次运行或打包前请安装依赖：`pip install -r requirements.txt`（运行时依赖）。
- 托盘图标使用项目目录下的 `tray/tray_icon.ico`，打包后自动嵌入 EXE。
- 端口配置文件位于 `%APPDATA%\VigilServe\tray-config.json`。
