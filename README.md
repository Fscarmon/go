# go
#!/bin/bash

# Go服务器API调用脚本

# 配置参数
SERVER_URL="http://localhost:8009"
API_TOKEN="your-secret-token-here"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 健康检查
check_health() {
    log_info "检查服务器健康状态..."
    
    response=$(curl -s -w "%{http_code}" -o /tmp/health_response.json \
        -X GET "${SERVER_URL}/health")
    
    if [ "$response" = "200" ]; then
        log_info "服务器健康状态正常"
        cat /tmp/health_response.json | jq '.' 2>/dev/null || cat /tmp/health_response.json
        return 0
    else
        log_error "服务器健康检查失败，HTTP状态码: $response"
        return 1
    fi
}

# 上传数据
upload_data() {
    local uuid="$1"
    local subname="$2"
    
    if [ -z "$uuid" ] || [ -z "$subname" ]; then
        log_error "参数错误: upload_data <UUID> <SUBNAME>"
        return 1
    fi
    
    log_info "上传数据 - UUID: $uuid, SUBNAME: $subname"
    
    # 构造JSON数据
    json_data=$(jq -n \
        --arg uuid "$uuid" \
        --arg subname "$subname" \
        '{UUID: $uuid, SUBNAME: $subname}')
    
    # 发送POST请求
    response=$(curl -s -w "%{http_code}" -o /tmp/upload_response.json \
        -X POST "${SERVER_URL}/upload?token=${API_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$json_data")
    
    if [ "$response" = "202" ]; then
        log_info "上传请求已接受"
        cat /tmp/upload_response.json | jq '.' 2>/dev/null || cat /tmp/upload_response.json
        return 0
    else
        log_error "上传失败，HTTP状态码: $response"
        cat /tmp/upload_response.json
        return 1
    fi
}

# 批量上传
batch_upload() {
    local csv_file="$1"
    
    if [ ! -f "$csv_file" ]; then
        log_error "CSV文件不存在: $csv_file"
        return 1
    fi
    
    log_info "开始批量上传，CSV文件: $csv_file"
    
    # 跳过标题行，读取CSV数据
    tail -n +2 "$csv_file" | while IFS=',' read -r uuid subname; do
        # 去除引号和空格
        uuid=$(echo "$uuid" | sed 's/[[:space:]]*//g' | sed 's/"//g')
        subname=$(echo "$subname" | sed 's/[[:space:]]*//g' | sed 's/"//g')
        
        if [ -n "$uuid" ] && [ -n "$subname" ]; then
            upload_data "$uuid" "$subname"
            sleep 1  # 避免请求过于频繁
        fi
    done
}

# 使用示例
show_usage() {
    echo "使用方法:"
    echo "  $0 health                           # 健康检查"
    echo "  $0 upload <UUID> <SUBNAME>         # 单个上传"
    echo "  $0 batch <CSV文件>                 # 批量上传"
    echo ""
    echo "CSV文件格式示例:"
    echo "  UUID,SUBNAME"
    echo "  server1-uuid,新服务器名称1"
    echo "  server2-uuid,新服务器名称2"
    echo ""
    echo "配置:"
    echo "  修改脚本顶部的 SERVER_URL 和 API_TOKEN"
}

# 主函数
main() {
    case "$1" in
        "health")
            check_health
            ;;
        "upload")
            if [ $# -ne 3 ]; then
                log_error "参数错误"
                show_usage
                exit 1
            fi
            upload_data "$2" "$3"
            ;;
        "batch")
            if [ $# -ne 2 ]; then
                log_error "参数错误"
                show_usage
                exit 1
            fi
            batch_upload "$2"
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

# 检查依赖
check_dependencies() {
    if ! command -v curl &> /dev/null; then
        log_error "curl 未安装，请安装 curl"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_warn "jq 未安装，JSON输出将不会格式化"
    fi
}

# 入口点
check_dependencies
main "$@"
