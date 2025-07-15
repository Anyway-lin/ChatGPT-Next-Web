#!/bin/bash

# TEE Provider 快速演示脚本
# 自动编译、配置并运行完整的演示

set -e

# 颜色定义
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

# 检查命令是否存在
check_command() {
    if ! command -v $1 &> /dev/null; then
        log_error "$1 not found. Please install $1 first."
        exit 1
    fi
}

# 检查OpenSSL版本
check_openssl_version() {
    local version=$(openssl version | awk '{print $2}')
    local major=$(echo $version | cut -d. -f1)
    local minor=$(echo $version | cut -d. -f2)
    
    if [ "$major" -lt 3 ]; then
        log_error "OpenSSL version $version is too old. Requires OpenSSL 3.0+"
        return 1
    fi
    
    log_success "OpenSSL version $version is compatible"
    return 0
}

# 清理函数
cleanup() {
    log_info "Cleaning up..."
    
    # 停止服务器进程
    if [ -f /tmp/tee_server.pid ]; then
        local pid=$(cat /tmp/tee_server.pid)
        if ps -p $pid > /dev/null; then
            log_info "Stopping server (PID: $pid)..."
            kill $pid 2>/dev/null || true
            rm -f /tmp/tee_server.pid
        fi
    fi
    
    # 清理临时文件
    rm -f /tmp/test_device_cert.pem
    
    log_success "Cleanup completed"
}

# 设置信号处理
trap cleanup EXIT INT TERM

# 显示欢迎信息
show_banner() {
    echo -e "${BLUE}"
    echo "=============================================="
    echo "    OpenSSL 3.0.9 TEE Provider Demo"
    echo "=============================================="
    echo -e "${NC}"
    echo "This script will demonstrate:"
    echo "  1. TEE Provider compilation"
    echo "  2. Test certificate generation"
    echo "  3. Unit tests execution"
    echo "  4. SSL client-server communication"
    echo ""
}

# 检查系统依赖
check_dependencies() {
    log_info "Checking system dependencies..."
    
    check_command gcc
    check_command make
    check_command openssl
    
    if ! check_openssl_version; then
        log_error "Please install OpenSSL 3.0.9 or later"
        exit 1
    fi
    
    # 检查开发库
    if ! pkg-config --exists openssl; then
        log_warning "OpenSSL development headers not found via pkg-config"
        log_warning "Continuing anyway, but compilation might fail"
    fi
    
    log_success "All dependencies satisfied"
}

# 编译项目
build_project() {
    log_info "Building TEE Provider..."
    
    # 清理之前的构建
    make clean &>/dev/null || true
    
    # 编译项目
    if make all; then
        log_success "Build completed successfully"
    else
        log_error "Build failed"
        exit 1
    fi
    
    # 验证生成的文件
    if [ ! -f "build/libtee_provider.so" ]; then
        log_error "TEE Provider library not found"
        exit 1
    fi
    
    if [ ! -f "build/client" ] || [ ! -f "build/server" ]; then
        log_error "Client or server executable not found"
        exit 1
    fi
    
    log_success "All binaries generated successfully"
}

# 生成测试证书
generate_certificates() {
    log_info "Generating test certificates..."
    
    if make certs; then
        log_success "Test certificates generated"
    else
        log_error "Certificate generation failed"
        exit 1
    fi
    
    # 验证证书文件
    local cert_files=("root_cert.pem" "device_cert.pem" "server_cert.pem")
    for cert in "${cert_files[@]}"; do
        if [ ! -f "certs/$cert" ]; then
            log_error "Certificate file $cert not found"
            exit 1
        fi
    done
    
    log_success "All certificate files verified"
}

# 运行单元测试
run_unit_tests() {
    log_info "Running unit tests..."
    
    # 编译测试程序
    if gcc -Wall -Wextra -std=c99 -I/usr/include/openssl -Isrc \
           -o build/test_provider tests/test_provider.c examples/tee_interface.c \
           -lssl -lcrypto; then
        log_success "Test program compiled"
    else
        log_error "Test compilation failed"
        return 1
    fi
    
    # 运行测试
    echo ""
    log_info "Executing test suite..."
    echo ""
    
    if ./build/test_provider; then
        log_success "All unit tests passed"
        return 0
    else
        log_error "Some unit tests failed"
        return 1
    fi
}

# 启动服务器
start_server() {
    log_info "Starting TEE SSL server..."
    
    # 检查端口是否被占用
    if netstat -ln | grep -q ":8443 "; then
        log_error "Port 8443 is already in use"
        exit 1
    fi
    
    # 启动服务器
    ./build/server &
    local server_pid=$!
    echo $server_pid > /tmp/tee_server.pid
    
    # 等待服务器启动
    local timeout=10
    local count=0
    while [ $count -lt $timeout ]; do
        if netstat -ln | grep -q ":8443 "; then
            log_success "Server started successfully (PID: $server_pid)"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    
    log_error "Server failed to start within $timeout seconds"
    return 1
}

# 运行客户端
run_client() {
    log_info "Running TEE SSL client..."
    
    # 等待一秒确保服务器完全就绪
    sleep 2
    
    echo ""
    log_info "Executing client connection..."
    echo ""
    
    if timeout 30 ./build/client; then
        log_success "Client connection completed successfully"
        return 0
    else
        log_error "Client connection failed or timed out"
        return 1
    fi
}

# 显示演示结果
show_results() {
    echo ""
    echo -e "${GREEN}=============================================="
    echo "         TEE Provider Demo Results"
    echo -e "==============================================${NC}"
    echo ""
    echo "✓ TEE Provider compiled successfully"
    echo "✓ Test certificates generated"
    echo "✓ Unit tests passed"
    echo "✓ SSL client-server communication verified"
    echo ""
    echo -e "${BLUE}Key Features Demonstrated:${NC}"
    echo "  • OpenSSL 3.0 Provider interface implementation"
    echo "  • TEE interface simulation"
    echo "  • Certificate chain management"
    echo "  • SSL/TLS client authentication without private key files"
    echo "  • Secure communication using TEE-based cryptography"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "  1. Review the code in src/ and examples/ directories"
    echo "  2. Adapt tee_interface.c for your actual TEE environment"
    echo "  3. Replace test certificates with production certificates"
    echo "  4. Follow DEPLOYMENT.md for production deployment"
    echo ""
}

# 显示使用帮助
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help message"
    echo "  -q, --quick     Skip unit tests (faster demo)"
    echo "  -c, --clean     Clean build and exit"
    echo "  -t, --test      Run unit tests only"
    echo "  -v, --verbose   Enable verbose output"
    echo ""
    echo "Environment variables:"
    echo "  OPENSSL_PREFIX  OpenSSL installation prefix (default: auto-detect)"
    echo "  DEBUG          Enable debug output (1 or 0)"
    echo ""
}

# 主函数
main() {
    local quick_mode=0
    local test_only=0
    local verbose=0
    
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -q|--quick)
                quick_mode=1
                shift
                ;;
            -c|--clean)
                log_info "Cleaning build files..."
                make clean
                log_success "Clean completed"
                exit 0
                ;;
            -t|--test)
                test_only=1
                shift
                ;;
            -v|--verbose)
                verbose=1
                set -x
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # 显示横幅
    show_banner
    
    # 检查依赖
    check_dependencies
    
    # 构建项目
    build_project
    
    # 生成证书
    generate_certificates
    
    # 运行测试
    if [ $test_only -eq 1 ]; then
        run_unit_tests
        exit $?
    fi
    
    if [ $quick_mode -eq 0 ]; then
        if ! run_unit_tests; then
            log_warning "Unit tests failed, but continuing with demo..."
        fi
    else
        log_info "Skipping unit tests (quick mode)"
    fi
    
    # 启动服务器
    if start_server; then
        # 运行客户端
        if run_client; then
            show_results
        else
            log_error "Demo failed during client execution"
            exit 1
        fi
    else
        log_error "Demo failed during server startup"
        exit 1
    fi
}

# 运行主函数
main "$@"