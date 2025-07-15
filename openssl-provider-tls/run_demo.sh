#!/bin/bash

# OpenSSL TEE Provider TLS演示脚本
# 此脚本将自动完成所有构建和测试步骤

set -e

PROJECT_NAME="OpenSSL TEE Provider TLS演示"
LOG_FILE="demo.log"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# 日志函数
log() {
    echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $1" | tee -a $LOG_FILE
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a $LOG_FILE
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a $LOG_FILE
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a $LOG_FILE
}

# 清理函数
cleanup() {
    if [ -n "$SERVER_PID" ]; then
        log "正在停止测试服务器 (PID: $SERVER_PID)..."
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
}

# 设置信号处理
trap cleanup EXIT

# 主函数
main() {
    clear
    echo -e "${BOLD}================================${NC}"
    echo -e "${BOLD}    $PROJECT_NAME    ${NC}"
    echo -e "${BOLD}================================${NC}"
    echo ""

    # 清理旧日志
    > $LOG_FILE

    log "开始演示，日志保存到: $LOG_FILE"

    # 步骤1：检查环境
    echo -e "${BOLD}步骤1: 检查环境${NC}"
    info "检查必要的工具和依赖..."
    
    # 检查基本工具
    for cmd in gcc make pkg-config openssl; do
        if ! command -v $cmd &> /dev/null; then
            error "缺少必要工具: $cmd"
            error "请运行: sudo apt-get install build-essential pkg-config libssl-dev openssl"
            exit 1
        fi
    done

    # 检查OpenSSL版本
    OPENSSL_VERSION=$(openssl version | awk '{print $2}')
    log "OpenSSL版本: $OPENSSL_VERSION"
    
    if ! pkg-config --exists openssl; then
        error "无法找到OpenSSL开发包"
        error "请运行: sudo apt-get install libssl-dev"
        exit 1
    fi

    log "✓ 环境检查通过"
    echo ""

    # 步骤2：编译项目
    echo -e "${BOLD}步骤2: 编译项目${NC}"
    log "开始编译TEE Provider和TLS应用..."
    
    make clean-all > /dev/null 2>&1 || true
    
    if ! make all 2>&1 | tee -a $LOG_FILE; then
        error "编译失败，请检查日志"
        exit 1
    fi
    
    log "✓ 编译完成"
    echo ""

    # 步骤3：生成证书
    echo -e "${BOLD}步骤3: 生成测试证书${NC}"
    log "生成根证书、中间证书和设备证书..."
    
    if ! make certs 2>&1 | tee -a $LOG_FILE; then
        error "证书生成失败"
        exit 1
    fi
    
    log "✓ 证书生成完成"
    echo ""

    # 步骤4：显示项目结构
    echo -e "${BOLD}步骤4: 项目结构${NC}"
    info "构建文件:"
    ls -la build/ | grep -E '\.(so|exe)$|tls_' | while read line; do
        echo "  $line"
    done
    
    echo ""
    info "证书文件:"
    ls -la certs/*.pem | while read line; do
        echo "  $line"
    done
    echo ""

    # 步骤5：启动测试服务器
    echo -e "${BOLD}步骤5: 启动TLS测试服务器${NC}"
    log "在后台启动TLS服务器 (端口8443)..."
    
    ./build/tls_server 8443 certs/server-cert.pem certs/server-key-nopass.pem > server.log 2>&1 &
    SERVER_PID=$!
    
    # 等待服务器启动
    sleep 2
    
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        error "服务器启动失败"
        cat server.log
        exit 1
    fi
    
    log "✓ TLS服务器启动成功 (PID: $SERVER_PID)"
    echo ""

    # 步骤6：运行TLS客户端测试
    echo -e "${BOLD}步骤6: 运行TEE Provider TLS客户端测试${NC}"
    log "使用TEE Provider执行TLS握手和数据传输..."
    
    echo -e "${YELLOW}=== TLS客户端输出 ===${NC}"
    
    if ./build/tls_client 127.0.0.1 8443 certs/device-key-nopass.pem certs/device-chain.pem certs/ca-cert.pem; then
        echo ""
        log "✓ TLS客户端测试成功！"
    else
        error "TLS客户端测试失败"
        echo ""
        echo -e "${YELLOW}=== 服务器日志 ===${NC}"
        cat server.log
        exit 1
    fi
    echo ""

    # 步骤7：显示测试结果
    echo -e "${BOLD}步骤7: 测试结果总结${NC}"
    echo ""
    echo -e "${GREEN}✓ 演示成功完成！${NC}"
    echo ""
    echo -e "${BOLD}测试验证的功能:${NC}"
    echo "  • TEE Provider成功加载并初始化"
    echo "  • 设备私钥安全加载到TEE Provider"
    echo "  • TLS握手使用TEE Provider进行私钥签名操作"
    echo "  • 三级证书链验证通过"
    echo "  • 双向TLS认证成功"
    echo "  • 加密数据传输正常"
    echo ""
    echo -e "${BOLD}技术特点:${NC}"
    echo "  • 私钥不直接暴露给应用程序"
    echo "  • 签名操作在TEE Provider内部完成"
    echo "  • 兼容标准OpenSSL TLS流程"
    echo "  • 支持完整的证书链验证"
    echo ""
    
    # 显示详细日志位置
    info "详细日志文件:"
    echo "  • 演示日志: $LOG_FILE"
    echo "  • 服务器日志: server.log"
    echo ""
    
    # 显示后续操作建议
    echo -e "${BOLD}后续操作建议:${NC}"
    echo "1. 查看详细日志了解内部工作流程"
    echo "2. 修改TEE Provider代码实现真实的TEE集成"
    echo "3. 集成到实际的IoT设备或应用中"
    echo "4. 根据需要调整证书策略和安全参数"
    echo ""
    
    log "演示完成"
}

# 检查是否在正确的目录
if [ ! -f "Makefile" ] || [ ! -d "src" ]; then
    error "请在项目根目录运行此脚本"
    echo "当前目录应包含 Makefile 和 src/ 目录"
    exit 1
fi

# 执行主函数
main

# 清理
cleanup