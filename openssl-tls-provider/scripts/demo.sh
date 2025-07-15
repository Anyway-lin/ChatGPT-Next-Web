#!/bin/bash

# 演示脚本
# 展示OpenSSL TLS Provider项目的完整使用流程

set -e

# 配置
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OPENSSL_PREFIX="/opt/openssl-3.0.9/dist"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 打印标题
print_title() {
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}============================================${NC}"
}

# 打印步骤
print_step() {
    echo -e "${BLUE}[步骤 $1]${NC} $2"
}

# 打印信息
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# 打印警告
print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# 暂停函数
pause() {
    echo -e "${YELLOW}按回车键继续...${NC}"
    read -r
}

# 主演示函数
main() {
    clear
    print_title "OpenSSL TLS Provider 项目演示"
    
    echo "本演示将展示如何使用基于OpenSSL 3.0.9的TEE Provider模型"
    echo "实现私钥安全操作和TLS握手。"
    echo
    pause
    
    cd "$PROJECT_DIR"
    
    # 步骤1: 环境检查
    print_step "1" "检查编译环境"
    print_info "检查OpenSSL 3.0.9是否正确安装..."
    
    if [ ! -f "$OPENSSL_PREFIX/bin/openssl" ]; then
        print_warning "OpenSSL 3.0.9未找到，请先安装到$OPENSSL_PREFIX"
        exit 1
    fi
    
    echo "OpenSSL版本信息:"
    $OPENSSL_PREFIX/bin/openssl version
    echo
    pause
    
    # 步骤2: 生成证书
    print_step "2" "生成测试证书"
    print_info "生成CA证书、服务器证书和客户端证书..."
    
    ./scripts/build.sh certs
    
    print_info "证书生成完成，查看生成的证书文件："
    ls -la certs/
    echo
    pause
    
    # 步骤3: 编译项目
    print_step "3" "编译项目"
    print_info "编译TEE Provider库、TLS客户端和服务器..."
    
    ./scripts/build.sh build
    
    print_info "编译完成，查看生成的文件："
    ls -la build/
    echo
    pause
    
    # 步骤4: 查看项目结构
    print_step "4" "项目结构说明"
    print_info "项目包含以下组件："
    
    cat << EOF

src/tee_provider.c    - TEE Provider实现，模拟TEE环境中的私钥操作
src/tls_client.c      - TLS客户端，使用TEE Provider进行握手
src/tls_server.c      - TLS服务器，用于测试客户端连接

build/libtee_provider.so - 编译生成的TEE Provider共享库
build/tls_client         - TLS客户端可执行文件
build/tls_server         - TLS服务器可执行文件

certs/                   - 生成的测试证书文件夹
EOF
    echo
    pause
    
    # 步骤5: 演示TLS握手
    print_step "5" "演示TLS握手"
    print_info "现在将演示完整的TLS握手过程..."
    
    print_info "启动TLS服务器（后台运行）..."
    ./build/tls_server -p 4433 &
    SERVER_PID=$!
    
    print_info "服务器PID: $SERVER_PID"
    sleep 2
    
    print_info "运行TLS客户端进行连接测试..."
    echo -e "${CYAN}客户端输出：${NC}"
    echo "----------------------------------------"
    ./build/tls_client -h 127.0.0.1 -p 4433
    echo "----------------------------------------"
    
    print_info "停止TLS服务器..."
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    
    echo
    pause
    
    # 步骤6: 解释关键特性
    print_step "6" "关键特性说明"
    print_info "本项目的关键特性："
    
    cat << EOF

1. TEE Provider模型：
   - 实现了OpenSSL 3.0.9的Provider接口
   - 模拟TEE环境中的私钥操作
   - 私钥操作对应用程序透明

2. 安全性：
   - 私钥操作封装在Provider内部
   - 应用程序无法直接访问私钥
   - 支持完整的TLS握手流程

3. 可扩展性：
   - 支持不同的证书配置
   - 可以集成到现有应用中
   - 提供完整的日志记录

4. 兼容性：
   - 基于OpenSSL 3.0.9标准接口
   - 支持标准TLS协议
   - 与现有TLS生态系统兼容
EOF
    echo
    pause
    
    # 步骤7: 使用建议
    print_step "7" "使用建议"
    print_info "在实际使用中的建议："
    
    cat << EOF

开发阶段：
1. 使用项目提供的测试证书进行开发
2. 修改代码以适应具体需求
3. 进行充分的测试验证

生产环境：
1. 使用正式的CA签发证书
2. 实现真正的TEE环境集成
3. 加强错误处理和日志记录
4. 进行安全审计和评估

扩展功能：
1. 支持更多加密算法
2. 实现密钥生命周期管理
3. 集成硬件安全模块(HSM)
4. 支持集群部署
EOF
    echo
    pause
    
    # 步骤8: 结束演示
    print_step "8" "演示完成"
    print_info "恭喜！您已经成功完成了OpenSSL TLS Provider项目的演示。"
    
    echo
    echo "接下来您可以："
    echo "1. 查看README.md了解更多详细信息"
    echo "2. 查看QUICKSTART.md了解快速使用方法"
    echo "3. 修改源代码以适应您的需求"
    echo "4. 集成到您的项目中"
    echo
    
    print_info "项目文件位置: $PROJECT_DIR"
    print_info "如有问题，请查看文档或提交Issue"
    
    print_title "感谢您的关注！"
}

# 清理函数
cleanup() {
    print_warning "演示被中断"
    # 确保服务器进程被终止
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
    fi
    exit 1
}

# 捕获中断信号
trap cleanup INT TERM

# 执行主函数
main "$@"