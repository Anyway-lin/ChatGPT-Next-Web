#!/bin/bash

echo "🎭 === OpenSSL Keyless 快速演示 ==="
echo ""

# 检查是否已构建
if [ ! -f "build/keyless_tls_server" ] || [ ! -f "build/simple_client" ]; then
    echo "📦 构建项目组件..."
    make all
    if [ $? -ne 0 ]; then
        echo "❌ 构建失败"
        exit 1
    fi
fi

echo "🚀 启动演示..."
echo ""

# 方式一：运行单进程演示
echo "🎭 方式一：运行完整单进程演示"
echo "================================="
make run-demo
echo ""

echo "🎭 方式二：演示服务器-客户端交互"
echo "================================="
echo "💡 提示：您可以在另一个终端运行以下命令来测试交互："
echo "   make run-server    # 启动服务器"
echo "   make run-client    # 启动客户端"
echo ""

echo "📋 可用的交互命令："
echo "   STATUS              - 获取服务器状态"
echo "   SIGN:Hello World    - 测试TEE签名功能"
echo "   Hello from client   - 回显测试"
echo "   quit                - 退出"
echo ""

echo "✅ 演示完成！"
echo ""
echo "📖 要了解更多，请查看："
echo "   📄 README.md          - 项目概述"
echo "   📄 docs/QUICKSTART.md - 快速启动指南"
echo "   📄 PROJECT_SUMMARY.md - 项目总结"
echo ""
echo "🔧 其他有用命令："
echo "   make help             - 显示所有可用命令"
echo "   make test             - 运行测试套件"
echo "   make info             - 显示项目信息"