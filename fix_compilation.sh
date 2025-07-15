#!/bin/bash

echo "==================================="
echo "OpenSSL TEE Provider 编译修复脚本"
echo "==================================="

# 检查是否在正确的目录
if [ ! -f "Makefile" ]; then
    echo "错误：请在包含Makefile的项目根目录运行此脚本"
    exit 1
fi

echo "步骤 1: 检查OpenSSL安装..."
if openssl version > /dev/null 2>&1; then
    echo "✓ OpenSSL 运行时已安装: $(openssl version)"
else
    echo "✗ OpenSSL 未安装"
    exit 1
fi

echo "步骤 2: 检查开发包..."
if pkg-config --exists openssl; then
    echo "✓ OpenSSL 开发包已安装"
elif [ -f "/usr/include/openssl/opensslv.h" ]; then
    echo "✓ OpenSSL 头文件找到"
elif [ -f "/usr/local/include/openssl/opensslv.h" ]; then
    echo "✓ OpenSSL 头文件找到 (本地安装)"
else
    echo "⚠ OpenSSL 开发包未找到，尝试安装..."
    if command -v apt-get > /dev/null; then
        echo "运行: sudo apt-get install libssl-dev"
        sudo apt-get update && sudo apt-get install -y libssl-dev
    elif command -v yum > /dev/null; then
        echo "运行: sudo yum install openssl-devel"
        sudo yum install -y openssl-devel
    elif command -v pacman > /dev/null; then
        echo "运行: sudo pacman -S openssl"
        sudo pacman -S openssl
    else
        echo "请手动安装OpenSSL开发包"
        echo "Ubuntu/Debian: sudo apt install libssl-dev"
        echo "CentOS/RHEL: sudo yum install openssl-devel"
        echo "Arch: sudo pacman -S openssl"
        exit 1
    fi
fi

echo "步骤 3: 验证源文件..."
required_files=(
    "src/tee_provider.h"
    "src/tee_provider.c"
    "examples/tee_interface.c"
    "examples/client.c"
    "examples/server.c"
)

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "✓ $file 存在"
    else
        echo "✗ $file 缺失"
        exit 1
    fi
done

echo "步骤 4: 应用编译修复..."

# 备份原文件
if [ -f "src/tee_provider.c.bak" ]; then
    echo "发现备份文件，跳过备份步骤"
else
    echo "创建备份文件..."
    cp src/tee_provider.c src/tee_provider.c.bak 2>/dev/null || true
    cp src/tee_provider.h src/tee_provider.h.bak 2>/dev/null || true
fi

# 修复 tee_provider.c 中的常量问题
echo "修复 Provider 参数常量..."
sed -i 's/OSSL_PROV_PARAM_NAME/"name"/g' src/tee_provider.c
sed -i 's/OSSL_PROV_PARAM_VERSION/"version"/g' src/tee_provider.c  
sed -i 's/OSSL_PROV_PARAM_BUILDINFO/"buildinfo"/g' src/tee_provider.c

echo "步骤 5: 测试编译..."
echo "运行: make clean"
make clean

echo "运行: make"
if make; then
    echo ""
    echo "🎉 编译成功！"
    echo ""
    echo "接下来可以运行："
    echo "  make test          # 运行单元测试"
    echo "  make demo          # 运行演示"
    echo "  ./run_demo.sh      # 完整演示"
    echo ""
else
    echo ""
    echo "❌ 编译失败"
    echo ""
    echo "可能的解决方案："
    echo "1. 检查 OpenSSL 版本是否为 3.0+"
    echo "2. 检查是否安装了 libssl-dev"
    echo "3. 检查编译器是否支持 C99"
    echo ""
    echo "详细错误信息请查看上面的编译输出"
    exit 1
fi

echo "==================================="
echo "修复完成！"
echo "==================================="