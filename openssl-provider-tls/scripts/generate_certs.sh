#!/bin/bash

set -e

# 创建证书目录
mkdir -p ../certs

cd ../certs

# 清理旧证书
rm -f *.pem *.key *.crt *.csr

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

# 创建服务器证书扩展配置
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = 127.0.0.1
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# 签发服务器证书
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -out server-cert.pem \
    -days 365 -CAcreateserial -extfile server.ext

echo "=== 生成客户端设备证书（三级证书链） ==="

# 生成中间CA私钥
openssl genpkey -algorithm RSA -out intermediate-key.pem

# 生成中间CA证书请求
openssl req -new -key intermediate-key.pem -out intermediate.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Test Intermediate CA/OU=IT Department/CN=Test Intermediate CA"

# 创建中间CA证书扩展配置
cat > intermediate.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:TRUE,pathlen:1
keyUsage = cRLSign, keyCertSign
EOF

# 签发中间CA证书
openssl x509 -req -in intermediate.csr -CA ca-cert.pem -CAkey ca-key.pem -out intermediate-cert.pem \
    -days 1825 -CAcreateserial -extfile intermediate.ext

# 生成设备私钥（这个私钥会被Provider使用）
openssl genpkey -algorithm RSA -out device-key.pem

# 生成设备证书请求
openssl req -new -key device-key.pem -out device.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=Test Device/OU=IoT Department/CN=Test Device 001"

# 创建设备证书扩展配置
cat > device.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# 签发设备证书
openssl x509 -req -in device.csr -CA intermediate-cert.pem -CAkey intermediate-key.pem \
    -out device-cert.pem -days 365 -CAcreateserial -extensions v3_req -extfile device.ext

# 创建完整的证书链
cat device-cert.pem intermediate-cert.pem ca-cert.pem > device-chain.pem

echo "=== 生成无密码私钥文件（用于Provider测试） ==="

# 创建无密码的设备私钥（模拟TEE环境中的私钥操作）
cp device-key.pem device-key-nopass.pem

# 创建无密码的服务器私钥
cp server-key.pem server-key-nopass.pem

echo "=== 验证证书链 ==="

# 验证设备证书链
openssl verify -CAfile ca-cert.pem -untrusted intermediate-cert.pem device-cert.pem

echo "=== 证书信息 ==="

echo "证书文件列表："
ls -la *.pem *.crt

echo ""
echo "设备证书信息："
openssl x509 -in device-cert.pem -text -noout | grep -A5 "Subject:"

echo ""
echo "服务器证书信息："
openssl x509 -in server-cert.pem -text -noout | grep -A5 "Subject:"

echo ""
echo "证书生成完成！"
echo "注意：为了简化演示，所有私钥都未设置密码"
echo "文件信息："
echo "  CA私钥: ca-key.pem (无密码)"
echo "  服务器私钥: server-key-nopass.pem (无密码)"
echo "  设备私钥: device-key-nopass.pem (无密码)"