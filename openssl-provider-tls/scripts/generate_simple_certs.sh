#!/bin/bash

set -e

# 创建证书目录
mkdir -p ../certs

cd ../certs

# 清理旧证书
rm -f *.pem *.key *.crt *.csr *.ext *.srl

echo "=== 生成根证书CA ==="

# 生成根证书私钥
openssl genpkey -algorithm RSA -out ca-key.pem

# 生成根证书
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 3650 \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Test CA/OU=IT Department/CN=Test Root CA"

echo "=== 生成服务器证书 ==="

# 生成服务器私钥
openssl genpkey -algorithm RSA -out server-key.pem

# 生成服务器证书请求
openssl req -new -key server-key.pem -out server.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Test Server/OU=IT Department/CN=localhost"

# 签发服务器证书
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -out server-cert.pem \
    -days 365 -CAcreateserial

echo "=== 生成客户端设备证书 ==="

# 生成设备私钥
openssl genpkey -algorithm RSA -out device-key.pem

# 生成设备证书请求
openssl req -new -key device-key.pem -out device.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Test Device/OU=IoT Department/CN=Test Device 001"

# 签发设备证书
openssl x509 -req -in device.csr -CA ca-cert.pem -CAkey ca-key.pem -out device-cert.pem \
    -days 365 -CAcreateserial

echo "=== 生成中间CA证书（可选，用于演示证书链） ==="

# 生成中间CA私钥
openssl genpkey -algorithm RSA -out intermediate-key.pem

# 生成中间CA证书请求
openssl req -new -key intermediate-key.pem -out intermediate.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Test Intermediate CA/OU=IT Department/CN=Test Intermediate CA"

# 签发中间CA证书
openssl x509 -req -in intermediate.csr -CA ca-cert.pem -CAkey ca-key.pem -out intermediate-cert.pem \
    -days 1825 -CAcreateserial

# 创建证书链文件
cat device-cert.pem ca-cert.pem > device-chain.pem

echo "=== 创建便于使用的文件 ==="

# 复制为无密码版本（已经是无密码的）
cp device-key.pem device-key-nopass.pem
cp server-key.pem server-key-nopass.pem

echo "=== 验证证书 ==="

# 验证服务器证书
echo "验证服务器证书:"
openssl verify -CAfile ca-cert.pem server-cert.pem

# 验证设备证书
echo "验证设备证书:"
openssl verify -CAfile ca-cert.pem device-cert.pem

echo "=== 证书信息 ==="

echo "证书文件列表："
ls -la *.pem

echo ""
echo "设备证书信息："
openssl x509 -in device-cert.pem -text -noout | grep -A3 "Subject:"

echo ""
echo "服务器证书信息："
openssl x509 -in server-cert.pem -text -noout | grep -A3 "Subject:"

echo ""
echo "✓ 证书生成完成！"
echo "注意：为了简化演示，所有私钥都未设置密码"
echo "文件说明："
echo "  ca-cert.pem         - 根CA证书"
echo "  server-cert.pem     - 服务器证书"
echo "  server-key-nopass.pem - 服务器私钥"
echo "  device-cert.pem     - 设备证书"
echo "  device-key-nopass.pem - 设备私钥"
echo "  device-chain.pem    - 设备证书链"