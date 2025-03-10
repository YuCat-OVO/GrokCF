# GrokCF

自动获取并更新验证 Cookie，保障服务的持续运行。

## 功能特性

- 🔍 支持 Flaresolverr/Byparr 解析器（自动处理 Cloudflare 验证）
- ⏲️ 可配置定时任务自动刷新 Cookie
- 📡 云防火墙凭证自动同步功能

## 快速开始

### 环境要求

- Python 3.10+
- Docker (用于运行 Flaresolverr)
- 支持的解析器服务：
    - [Flaresolverr](https://github.com/FlareSolverr/FlareSolverr)
    - [Byparr](https://github.com/ThePhaseless/Byparr) (未验证)

### 安装步骤

1. 克隆仓库

```bash
git clone https://github.com/YuCat-OVO/GrokCF.git
cd GrokCF
```

2. 安装依赖

```bash
pip install -r requirements.txt
```

3. 启动 Flaresolverr 服务

```bash
docker run -d \
  --name=flaresolverr \
  -p 8191:8191 \
  -e LOG_LEVEL=info \
  --restart unless-stopped \
  ghcr.io/flaresolverr/flaresolverr:latest
```

### 运行服务

#### 直接运行
```bash
python main.py
```

#### 使用 Podman
```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grokcf
  annotations:
    io.containers.autoupdate: registry
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grokcf
  template:
    metadata:
      labels:
        app: grokcf
    spec:
      restartPolicy: Always
      containers:
        - name: grokcf
          image: docker.io/yucatovo/grokcf:latest
          env:
            - name: TZ
              value: "Asia/Shanghai"
```

## 配置项详解

| 环境变量                | 必填 | 默认值                                    | 说明          |
|---------------------|----|----------------------------------------|-------------|
| `SOLVER_URL`        | 是  | `http://localhost:8191`                | 解析器服务地址     |
| `SOLVER_TYPE`       | 是  | `flaresolverr`                         | 使用的解析器类型    |
| `TARGET_URL`        | 是  | -                                      | 需要绕过的目标网站   |
| `SOLVER_TIMEOUT`    | 否  | 200000                                 | 解析器超时时间（毫秒） |
| `UPDATE_ENDPOINT`   | 是  | http://localhost:8000/set/cf_clearance | 凭证更新API地址   |
| `ENDPOINT_AUTH`     | 是  | sk-123456                              | 端点认证密钥      |
| `INTERVAL`          | 否  | 300                                    | 自动刷新间隔（秒）   |
| `MIN_EXEC_INTERVAL` | 否  | 10                                     | 最小任务间隔保护    |
| `PROXY`             | 否  | -                                      | 代理服务器地址     |

## 注意事项

- Byparr 解析器暂不支持代理认证，需要在其服务部署的时候设置
