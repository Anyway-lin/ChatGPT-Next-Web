#!/bin/bash

# 构建脚本
# 基于OpenSSL 3.0.9的TEE Provider模型

set -e

# 配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OPENSSL_PREFIX="/usr"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
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

# 检查OpenSSL安装
check_openssl() {
    log_info "检查OpenSSL安装..."
    
    if [ ! -d "$OPENSSL_PREFIX" ]; then
        log_error "OpenSSL未安装在$OPENSSL_PREFIX"
        log_info "请先安装OpenSSL开发包"
        exit 1
    fi
    
    if [ ! -f "$OPENSSL_PREFIX/bin/openssl" ]; then
        log_error "OpenSSL二进制文件不存在: $OPENSSL_PREFIX/bin/openssl"
        exit 1
    fi
    
    local version=$($OPENSSL_PREFIX/bin/openssl version)
    log_success "OpenSSL版本: $version"
    
    # 检查必要的库文件
    if [ ! -f "$OPENSSL_PREFIX/lib64/libssl.so" ] && [ ! -f "$OPENSSL_PREFIX/lib/libssl.so" ] && [ ! -f "$OPENSSL_PREFIX/lib/x86_64-linux-gnu/libssl.so.3" ]; then
        log_error "OpenSSL库文件不存在"
        exit 1
    fi
    
    log_success "OpenSSL环境检查通过"
}

# 检查编译环境
check_build_env() {
    log_info "检查编译环境..."
    
    # 检查gcc
    if ! command -v gcc &> /dev/null; then
        log_error "gcc编译器未安装"
        log_info "请安装gcc: sudo apt-get install gcc"
        exit 1
    fi
    
    # 检查make
    if ! command -v make &> /dev/null; then
        log_error "make工具未安装"
        log_info "请安装make: sudo apt-get install make"
        exit 1
    fi
    
    # 检查必要的头文件
    if [ ! -f "$OPENSSL_PREFIX/include/openssl/ssl.h" ]; then
        log_error "OpenSSL头文件不存在"
        exit 1
    fi
    
    log_success "编译环境检查通过"
}

# 生成证书
generate_certs() {
    log_info "生成测试证书..."
    
    cd "$PROJECT_DIR"
    make certs
    
    log_success "证书生成完成"
}

# 编译项目
build_project() {
    log_info "编译项目..."
    
    cd "$PROJECT_DIR"
    
    # 清理之前的构建
    make clean
    
    # 编译
    make all
    
    log_success "项目编译完成"
}

# 运行测试
run_test() {
    log_info "运行测试..."
    
    cd "$PROJECT_DIR"
    
    # 检查构建文件是否存在
    if [ ! -f "build/tls_server" ] || [ ! -f "build/tls_client" ]; then
        log_error "构建文件不存在，请先编译项目"
        exit 1
    fi
    
    # 启动服务器
    log_info "启动TLS服务器（端口4433）..."
    ./build/tls_server -p 4433 &
    SERVER_PID=$!
    
    # 等待服务器启动
    sleep 2
    
    # 测试客户端连接
    log_info "运行TLS客户端测试..."
    if ./build/tls_client -h 127.0.0.1 -p 4433; then
        log_success "TLS连接测试成功"
    else
        log_error "TLS连接测试失败"
    fi
    
    # 停止服务器
    log_info "停止TLS服务器..."
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    
    log_success "测试完成"
}

# 安装程序
install_program() {
    log_info "安装程序..."
    
    cd "$PROJECT_DIR"
    make install
    
    log_success "程序安装完成"
}

# 卸载程序
uninstall_program() {
    log_info "卸载程序..."
    
    cd "$PROJECT_DIR"
    make uninstall
    
    log_success "程序卸载完成"
}

# 清理文件
clean_files() {
    log_info "清理构建文件..."
    
    cd "$PROJECT_DIR"
    make clean
    
    log_success "构建文件清理完成"
}

# 显示帮助
show_help() {
    cat << EOF
OpenSSL TLS Provider 构建脚本

使用方法: $0 [选项]

选项:
    check       - 检查编译环境
    certs       - 生成测试证书
    build       - 编译项目
    test        - 运行测试
    install     - 安装程序
    uninstall   - 卸载程序
    clean       - 清理构建文件
    all         - 执行完整构建流程（check + certs + build + test）
    help        - 显示此帮助信息

示例:
    $0 all              # 完整构建流程
    $0 build            # 仅编译
    $0 test             # 仅测试
    $0 certs            # 仅生成证书

 注意事项:
     - 确保OpenSSL已安装在 $OPENSSL_PREFIX
     - 需要sudo权限进行安装/卸载操作
     - 测试需要使用端口4433，确保该端口未被占用
EOF
}

# 主函数
main() {
    echo "=========================================="
    echo "OpenSSL TLS Provider 构建脚本"
    echo "=========================================="
    
    case "${1:-all}" in
        "check")
            check_openssl
            check_build_env
            ;;
        "certs")
            check_openssl
            generate_certs
            ;;
        "build")
            check_openssl
            check_build_env
            build_project
            ;;
        "test")
            check_openssl
            run_test
            ;;
        "install")
            install_program
            ;;
        "uninstall")
            uninstall_program
            ;;
        "clean")
            clean_files
            ;;
        "all")
            check_openssl
            check_build_env
            generate_certs
            build_project
            run_test
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
    
    echo "=========================================="
    log_success "操作完成"
}

# 捕获中断信号
trap 'echo; log_warning "操作被中断"; exit 1' INT TERM

# 执行主函数
main "$@"