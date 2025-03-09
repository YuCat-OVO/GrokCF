#!/bin/sh

# 检查依赖命令是否存在
command -v curl >/dev/null 2>&1 || { echo "需要curl但未安装"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "需要jq但未安装"; exit 1; }

# 从环境变量获取配置
FLARESOLVERR_URL=${FLARESOLVERR_URL:-http://flaresolverr:8191/v1}
TARGET_URL=${TARGET_URL:-https://grok.com}
UPDATE_ENDPOINT=${UPDATE_ENDPOINT:-http://example:3000/set/cf_clearance}
INTERVAL=${INTERVAL:-300}
PROXY_URL=${PROXY_URL:-}

# 验证必要参数
if [ -z "$FLARESOLVERR_URL" ] || [ -z "$UPDATE_ENDPOINT" ] || [ -z "$TARGET_URL" ]; then
    echo "错误：必须设置环境变量 FLARESOLVERR_URL, TARGET_URL 和 UPDATE_ENDPOINT"
    exit 1
fi

# 解析代理参数
parse_proxy() {
    if [ -z "$PROXY_URL" ]; then
        return 0
    fi

    # 提取协议头
    scheme=$(echo "$PROXY_URL" | sed -n 's#^\([a-zA-Z][a-zA-Z0-9+.-]*\)://.*#\1#p')
    if [ -z "$scheme" ]; then
        echo "错误：代理URL必须包含协议头 (http://, socks5:// 等)"
        exit 1
    fi

    # 提取用户信息和主机端口
    rest=$(echo "$PROXY_URL" | sed 's#^[^:]\+://##')
    userinfo_hostport=$(echo "$rest" | awk -F/ '{print $1}')

    # 分离用户信息和主机端口
    userinfo=$(echo "$userinfo_hostport" | awk -F@ '{print $1}')
    hostport=$(echo "$userinfo_hostport" | awk -F@ 'NF>1 {print $2}')
    [ -z "$hostport" ] && hostport=$userinfo_hostport

    # 提取主机和端口
    host=$(echo "$hostport" | sed -nE 's/^(\[[0-9a-fA-F:]+\]|[^:]*)(:([0-9]+))?$/\1/p')
    port=$(echo "$hostport" | sed -nE 's/^(\[[0-9a-fA-F:]+\]|[^:]*)(:([0-9]+))?$/\3/p')

    # 设置默认端口
    case $scheme in
        http)   default_port=80 ;;
        https)  default_port=443 ;;
        socks4) default_port=1080 ;;
        socks5) default_port=1080 ;;
        *)       echo "错误：不支持的协议类型 $scheme"; exit 1 ;;
    esac
    [ -z "$port" ] && port=$default_port

    # 提取用户名密码
    username=$(echo "$userinfo" | cut -d: -f1)
    password=$(echo "$userinfo" | cut -d: -f2-)

    # 构建代理URL
    proxy_url="$scheme://$host:$port"
}

# 解析代理配置
parse_proxy

while true
do
    echo "$(date) - 开始请求CloudFlare验证..."

    # 动态生成请求JSON
    request_json=$(jq -n \
        --arg cmd "request.get" \
        --arg url "$TARGET_URL" \
        --arg proxy_url "$proxy_url" \
        --arg username "$username" \
        --arg password "$password" \
        '{
            cmd: $cmd,
            url: $url,
            proxy: (if $proxy_url != "" then {
                url: $proxy_url,
                username: (if $username != "" then $username else null end),
                password: (if $password != "" then $password else null end)
            } else null end)
        } | del(.proxy | nulls)')

    # 通过FlareSolverr请求目标网站
    response=$(curl -s -X POST "$FLARESOLVERR_URL" \
        -H "Content-Type: application/json" \
        -d "$request_json")

    # 提取cf_clearance值
    cf_clearance=$(echo "$response" | jq -r '.solution.cookies[] | select(.name == "cf_clearance") | .value')

    if [ -n "$cf_clearance" ]; then
        echo "$(date) - 获取到新Cookie: $cf_clearance"
        
        # 更新Cookie到目标服务
        update_result=$(curl -s -X POST "$UPDATE_ENDPOINT" \
            -H "Content-Type: application/json" \
            -d "{\"cf_clearance\": \"$cf_clearance\"}")
            
        echo "$(date) - 更新结果: $update_result"
    else
        echo "$(date) - 错误: 未能获取cf_clearance"
        echo "原始响应: $response"
    fi

    # 等待指定间隔
    sleep "$INTERVAL"
done
