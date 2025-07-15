#!/bin/bash

set -e

echo "====================================================================="
echo "           TEE Provider OpenSSL 3.x 演示"
echo "====================================================================="
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 辅助函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查依赖
check_dependencies() {
    log_info "检查系统依赖..."
    
    # 检查OpenSSL版本
    if command -v openssl &> /dev/null; then
        OPENSSL_VERSION=$(openssl version | grep -o '3\.[0-9]*\.[0-9]*')
        if [[ -n "$OPENSSL_VERSION" ]]; then
            log_success "OpenSSL 版本: $OPENSSL_VERSION"
        else
            log_error "需要 OpenSSL 3.x 版本"
            exit 1
        fi
    else
        log_error "未找到 OpenSSL"
        exit 1
    fi
    
    # 检查CMake
    if ! command -v cmake &> /dev/null; then
        log_error "未找到 CMake"
        exit 1
    fi
    
    # 检查gcc
    if ! command -v gcc &> /dev/null; then
        log_error "未找到 GCC 编译器"
        exit 1
    fi
    
    # 检查必要的开发库
    if ! pkg-config --exists libssl; then
        log_warning "可能缺少 libssl-dev 包"
    fi
    
    log_success "依赖检查完成"
}

# 清理旧文件
cleanup() {
    log_info "清理旧的构建文件..."
    rm -rf build
    rm -rf certs
    log_success "清理完成"
}

# 生成证书
generate_certificates() {
    log_info "生成测试证书..."
    
    if [[ ! -x "./generate_certs.sh" ]]; then
        chmod +x generate_certs.sh
    fi
    
    ./generate_certs.sh
    
    if [[ -f "certs/device_cert.pem" && -f "certs/server_cert.pem" ]]; then
        log_success "证书生成成功"
    else
        log_error "证书生成失败"
        exit 1
    fi
}

# 编译项目
build_project() {
    log_info "编译项目..."
    
    mkdir -p build
    cd build
    
    cmake .. -DCMAKE_BUILD_TYPE=Debug
    make -j$(nproc)
    
    cd ..
    
    # 复制证书到build目录
    if [[ -d "certs" ]]; then
        cp -r certs build/
        log_info "证书文件已复制到build目录"
    fi
    
    if [[ -f "build/tls_client" && -f "build/test_server" ]]; then
        log_success "项目编译成功"
    else
        log_error "项目编译失败"
        exit 1
    fi
}

# 启动服务器
start_server() {
    local port=${1:-8443}
    log_info "启动测试服务器在端口 $port..."
    
    cd build
    ./test_server $port &
    SERVER_PID=$!
    cd ..
    
    # 等待服务器启动
    sleep 2
    
    if kill -0 $SERVER_PID 2>/dev/null; then
        log_success "服务器启动成功 (PID: $SERVER_PID)"
        return 0
    else
        log_error "服务器启动失败"
        return 1
    fi
}

# 运行客户端
run_client() {
    local host=${1:-127.0.0.1}
    local port=${2:-8443}
    
    log_info "运行TLS客户端连接到 $host:$port..."
    
    cd build
    ./tls_client $host $port
    cd ..
}

# 停止服务器
stop_server() {
    if [[ -n "$SERVER_PID" ]]; then
        log_info "停止服务器..."
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
        log_success "服务器已停止"
    fi
}

# 信号处理
trap stop_server EXIT INT TERM

# 显示帮助
show_help() {
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help          显示帮助信息"
    echo "  -c, --clean         清理旧文件后退出"
    echo "  -b, --build-only    仅编译项目"
    echo "  -s, --server-only   仅启动服务器"
    echo "  -p, --port PORT     指定服务器端口 (默认: 8443)"
    echo "  --host HOST         指定连接主机 (默认: 127.0.0.1)"
    echo "  --no-demo           不运行演示"
    echo ""
    echo "环境变量:"
    echo "  TEE_DEBUG=1         启用详细调试输出"
    echo ""
}

# 主函数
main() {
    local clean_only=false
    local build_only=false
    local server_only=false
    local run_demo=true
    local port=8443
    local host="127.0.0.1"
    
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--clean)
                clean_only=true
                shift
                ;;
            -b|--build-only)
                build_only=true
                shift
                ;;
            -s|--server-only)
                server_only=true
                shift
                ;;
            -p|--port)
                port="$2"
                shift 2
                ;;
            --host)
                host="$2"
                shift 2
                ;;
            --no-demo)
                run_demo=false
                shift
                ;;
            *)
                log_error "未知选项: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # 执行步骤
    check_dependencies
    
    if [[ "$clean_only" == true ]]; then
        cleanup
        log_success "清理完成"
        exit 0
    fi
    
    cleanup
    generate_certificates
    build_project
    
    if [[ "$build_only" == true ]]; then
        log_success "编译完成"
        echo ""
        echo "手动运行命令:"
        echo "  启动服务器: cd build && ./test_server $port"
        echo "  运行客户端: cd build && ./tls_client $host $port"
        exit 0
    fi
    
    if [[ "$server_only" == true ]]; then
        log_info "仅服务器模式，按Ctrl+C停止"
        start_server $port
        while true; do
            sleep 1
        done
    fi
    
    if [[ "$run_demo" == true ]]; then
        echo ""
        log_info "开始TEE Provider演示..."
        echo ""
        
        # 启动服务器
        if start_server $port; then
            sleep 1
            
            # 运行客户端
            echo ""
            echo "====== 客户端输出 ======"
            run_client $host $port
            echo "======================="
            echo ""
            
            log_success "演示完成！"
        else
            log_error "无法启动服务器"
            exit 1
        fi
    fi
}

# 检查是否在正确的目录
if [[ ! -f "tee_provider.h" ]]; then
    log_error "请在包含tee_provider.h的目录中运行此脚本"
    exit 1
fi

# 运行主函数
main "$@"