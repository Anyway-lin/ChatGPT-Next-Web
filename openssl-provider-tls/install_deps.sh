#!/bin/bash

echo "=== 安装OpenSSL TEE Provider TLS项目依赖 ==="

# 检查是否有sudo权限
if ! sudo -v 2>/dev/null; then
    echo "错误：需要sudo权限来安装系统包"
    echo "请运行: sudo ./install_deps.sh"
    exit 1
fi

echo "更新包列表..."
sudo apt-get update

echo "安装编译依赖..."
sudo apt-get install -y \
    build-essential \
    gcc \
    make \
    pkg-config \
    libssl-dev \
    openssl

echo "验证安装结果..."
echo "GCC版本:"
gcc --version | head -1

echo "OpenSSL版本:"
openssl version

echo "检查OpenSSL头文件:"
if [ -f /usr/include/openssl/ssl.h ]; then
    echo "✓ OpenSSL头文件安装成功"
else
    echo "✗ OpenSSL头文件未找到"
    exit 1
fi

echo "检查OpenSSL库文件:"
if ldconfig -p | grep -q libssl; then
    echo "✓ OpenSSL库文件可用"
else
    echo "✗ OpenSSL库文件未找到"
    exit 1
fi

echo ""
echo "✓ 所有依赖安装完成！"
echo "现在可以运行: make all"