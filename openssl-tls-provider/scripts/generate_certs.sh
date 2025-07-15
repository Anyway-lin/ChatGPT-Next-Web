#!/bin/bash

# 证书生成脚本
# 基于OpenSSL 3.0.9生成测试证书

OPENSSL_PATH="/usr/bin/openssl"
CERT_DIR="certs"
DAYS=365

echo "=== 生成测试证书 ==="

# 创建证书目录
mkdir -p $CERT_DIR

# 检查OpenSSL版本
echo "OpenSSL版本:"
$OPENSSL_PATH version

# 1. 生成CA私钥
echo "1. 生成CA私钥..."
$OPENSSL_PATH genrsa -out $CERT_DIR/ca.key 2048

# 2. 生成CA证书
echo "2. 生成CA证书..."
$OPENSSL_PATH req -new -x509 -key $CERT_DIR/ca.key -out $CERT_DIR/ca.crt -days $DAYS -subj "/C=CN/ST=Beijing/L=Beijing/O=Test CA/OU=Test CA/CN=Test CA"

# 3. 生成服务器私钥
echo "3. 生成服务器私钥..."
$OPENSSL_PATH genrsa -out $CERT_DIR/server.key 2048

# 4. 生成服务器证书签名请求
echo "4. 生成服务器证书签名请求..."
$OPENSSL_PATH req -new -key $CERT_DIR/server.key -out $CERT_DIR/server.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=Test Server/OU=Test Server/CN=localhost"

# 5. 生成服务器证书
echo "5. 生成服务器证书..."
$OPENSSL_PATH x509 -req -in $CERT_DIR/server.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key -CAcreateserial -out $CERT_DIR/server.crt -days $DAYS

# 6. 生成客户端私钥
echo "6. 生成客户端私钥..."
$OPENSSL_PATH genrsa -out $CERT_DIR/client.key 2048

# 7. 生成客户端证书签名请求
echo "7. 生成客户端证书签名请求..."
$OPENSSL_PATH req -new -key $CERT_DIR/client.key -out $CERT_DIR/client.csr -subj "/C=CN/ST=Beijing/L=Beijing/O=Test Client/OU=Test Client/CN=client"

# 8. 生成客户端证书
echo "8. 生成客户端证书..."
$OPENSSL_PATH x509 -req -in $CERT_DIR/client.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key -CAcreateserial -out $CERT_DIR/client.crt -days $DAYS

# 9. 转换为PEM格式
echo "9. 转换为PEM格式..."
cp $CERT_DIR/ca.crt $CERT_DIR/ca.pem
cp $CERT_DIR/server.crt $CERT_DIR/server.pem
cp $CERT_DIR/client.crt $CERT_DIR/client.pem
cp $CERT_DIR/client.key $CERT_DIR/client.pem.key

# 10. 验证证书
echo "10. 验证证书..."
echo "CA证书信息:"
$OPENSSL_PATH x509 -in $CERT_DIR/ca.pem -text -noout | grep -E "Subject:|Issuer:|Valid"

echo "服务器证书信息:"
$OPENSSL_PATH x509 -in $CERT_DIR/server.pem -text -noout | grep -E "Subject:|Issuer:|Valid"

echo "客户端证书信息:"
$OPENSSL_PATH x509 -in $CERT_DIR/client.pem -text -noout | grep -E "Subject:|Issuer:|Valid"

# 11. 验证证书链
echo "11. 验证证书链..."
$OPENSSL_PATH verify -CAfile $CERT_DIR/ca.pem $CERT_DIR/server.pem
$OPENSSL_PATH verify -CAfile $CERT_DIR/ca.pem $CERT_DIR/client.pem

echo "=== 证书生成完成 ==="
echo "生成的文件:"
ls -la $CERT_DIR/

echo ""
echo "使用说明:"
echo "CA证书: $CERT_DIR/ca.pem"
echo "服务器证书: $CERT_DIR/server.pem"
echo "服务器私钥: $CERT_DIR/server.key"
echo "客户端证书: $CERT_DIR/client.pem"
echo "客户端私钥: $CERT_DIR/client.key"