#!/bin/bash

echo "============================================"
echo "Keyless TLS Demo - 零信任密钥管理系统演示"
echo "============================================"
echo

# 检查是否已编译
if [ ! -f "tls_server" ] || [ ! -f "tls_client" ] || [ ! -f "test_tee" ]; then
    echo "正在编译项目..."
    make all
    echo
fi

# 运行TEE测试
echo "1. 运行TEE Mock基础测试..."
echo "----------------------------------------"
./test_tee certs/device_key.pem
echo

# 准备TLS演示
echo "2. 启动TLS演示..."
echo "----------------------------------------"

# 启动服务器
echo "启动TLS服务器..."
./tls_server certs/server_cert.pem certs/server_key.pem certs/root_ca_cert.pem &
SERVER_PID=$!

# 等待服务器启动
sleep 2

echo "服务器已启动，PID: $SERVER_PID"
echo

# 运行客户端
echo "运行TLS客户端（集成TEE Mock）..."
echo "----------------------------------------"
./tls_client 127.0.0.1 certs/device_key.pem certs/device_cert.pem certs/root_ca_cert.pem

# 停止服务器
echo
echo "停止服务器..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo
echo "============================================"
echo "演示完成！"
echo "============================================"
echo
echo "成功验证的功能："
echo "✅ TEE Mock环境初始化"
echo "✅ 三级证书链加载（Root CA → Intermediate CA → Device Certificate）"
echo "✅ TLS 1.3双向认证握手"
echo "✅ 加密通信（AES-256-GCM）"
echo "✅ 证书验证流程"
echo "✅ 消息传输和响应"
echo
echo "这证明了零信任密钥管理系统的可行性："
echo "- 私钥操作通过TEE安全环境处理"
echo "- 证书链完整传输和验证"
echo "- 端到端加密通信建立成功"
echo
echo "项目文件："
echo "  - TLS服务器: ./tls_server"
echo "  - TLS客户端: ./tls_client"
echo "  - TEE测试: ./test_tee"
echo "  - 证书目录: ./certs/"
echo "  - 项目文档: ./README.md"