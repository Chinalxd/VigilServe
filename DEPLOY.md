# 部署指南

> 2026-09-23 修订：本文原先写的「方式一：Docker Compose 部署（推荐）」**并不存在** ——
> 仓库里只有 `backend/Dockerfile` 与 `frontend/Dockerfile` 两个镜像构建文件，没有
> `docker-compose.yml`，照抄那段命令会直接失败。下面改为按实际可用的方式排序。

## 方式一：Windows 安装包部署（推荐，与生产一致）

生产环境跑在 Windows 上：一个 Inno Setup 打出来的安装包，装完由托盘程序
（`VigilServeTray.exe`）拉起后端并常驻，内置便携 Python 运行时，目标机不需要预装 Python。

```bat
:: 1) 构建（在源码目录，需 Inno Setup 7 + 已 build 过前端/托盘/Agent）
python installer\build_installer.py

:: 2) 产物落在 installer\output\ 并自动同步到 F:\VigilServe
::    VigilServe-Setup-<版本>.exe   —— 服务端安装包（托盘 exe 已打在里面）
::    VigilServeAgent-Setup-<版本>.exe —— Agent 安装包（分发到被监控主机）
```

被监控主机上装 Agent 安装包即可，Agent 是**出站注册**（主动连服务端），
服务端不回调 Agent，所以被监控主机不需要放行入站端口。

访问：`https://<服务器IP>:8001`（生产默认 HTTPS；WEB 管理反向代理另占 8009）。

## 方式二：Docker（仅有镜像构建文件，需自行编排）

仓库里只有 `backend/Dockerfile`、`frontend/Dockerfile`，**没有编排文件**，
本方式未经过验证、生产也不用它。要用请自行补 `docker-compose.yml` 与端口/卷映射：

```bash
docker build -t vigilserve-backend ./backend
docker build -t vigilserve-frontend ./frontend
```

## 方式三：手动部署

### 后端

```bash
cd backend
pip install -r requirements.txt

# 直接运行
uvicorn main:app --host 0.0.0.0 --port 8000

# 或使用 systemd 管理
```

### 前端

```bash
cd frontend
npm ci
npm run build

# 将 dist/ 目录部署到 nginx
cp -r dist/ /var/www/vigilserve/
```

配置 nginx（参考 frontend/nginx.conf）。

## 方式四：开发模式直接运行

```bash
# 终端 1 - 后端
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000

# 终端 2 - 前端
cd frontend
npm ci
npm run dev
```

访问 `http://localhost:3000`。

## 配置说明

数据库路径**不是**环境变量，是 `backend/database.py` 里写死的
`{backend 目录}/monitor.db`（改它要动代码）。实际生效的环境变量如下：

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `PRODUCTION` | `0` | 设 `1` 才由本进程托管 `frontend/dist`，并强制 HTTPS |
| `VIGILSERVE_BACKEND_PORT` | `8000` | 后端监听端口（生产常用 8001） |
| `VIGILSERVE_TLS` | `1` | 设 `0` 关闭 HTTPS，**明文运行**，仅限排障 |
| `VIGILSERVE_TLS_INSECURE_FALLBACK` | 未设 | 设 `1` 才允许证书准备失败时降级为 HTTP |
| `VIGILSERVE_ALLOWED_ORIGINS` | 空（仅同源） | 逗号分隔的 CORS 白名单 |
| `VIGILSERVE_WEBPROXY_PORT` | `8009` | 网络设备「WEB管理」独立源代理端口 |
| `VIGILSERVE_WEBPROXY_TLS` | `1` | 设 `0` 让代理以 HTTP 提供（跨源 iframe 里自签证书会被静默拦截） |
| `VIGILSERVE_WEBPROXY_PREFIX` | `/web/` | 独立源代理的路径前缀 |

Agent 侧：`VIGILSERVE_AGENT_ALLOW_PLAINTEXT=1` 才允许 9998 在无 TLS 时以明文监听
（默认 fail closed，拿不到证书就不监听）。

## 发布前自检

```bash
python verify_version.py     # 校验 9 处版本号是否跟随真源
```

真源只有两处：`backend/main.py` 的 `FastAPI(version=...)`（服务端）与
`agent/api_server.py` 的 `AGENT_VERSION`（Agent），其余位置都应跟随。

生产环境建议：
- 保持 `PRODUCTION=1`，全链路 HTTPS
- 首装后立即改掉默认管理员口令（见 README「安全提示」）
