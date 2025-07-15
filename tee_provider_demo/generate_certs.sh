#!/bin/bash

# 生成TEE Provider演示所需的证书链
set -e

echo "=== 生成TEE Provider演示证书链 ==="

# 清理之前的文件
rm -rf certs
mkdir -p certs
cd certs

# 1. 生成根CA私钥和证书
echo "1. 生成根CA证书..."
openssl genrsa -out root_ca_key.pem 4096
openssl req -new -x509 -key root_ca_key.pem -out root_ca_cert.pem -days 3650 \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=TEE Demo/OU=Root CA/CN=TEE Root CA"

# 2. 生成中间CA私钥和证书请求
echo "2. 生成中间CA证书..."
openssl genrsa -out intermediate_ca_key.pem 4096
openssl req -new -key intermediate_ca_key.pem -out intermediate_ca_csr.pem \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=TEE Demo/OU=Intermediate CA/CN=TEE Intermediate CA"

# 3. 使用根CA签发中间CA证书
cat > intermediate_ca_ext.conf << EOF
[v3_ca]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

openssl x509 -req -in intermediate_ca_csr.pem -CA root_ca_cert.pem -CAkey root_ca_key.pem \
    -out intermediate_ca_cert.pem -days 1825 -extensions v3_ca -extfile intermediate_ca_ext.conf \
    -CAcreateserial

# 4. 生成设备私钥和证书请求
echo "3. 生成设备证书..."
openssl genrsa -out device_key.pem 2048
openssl req -new -key device_key.pem -out device_csr.pem \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=TEE Demo/OU=Device/CN=TEE Device"

# 5. 使用中间CA签发设备证书
cat > device_ext.conf << EOF
[v3_req]
basicConstraints = CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = tee-device.local
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in device_csr.pem -CA intermediate_ca_cert.pem -CAkey intermediate_ca_key.pem \
    -out device_cert.pem -days 365 -extensions v3_req -extfile device_ext.conf \
    -CAcreateserial

# 6. 创建完整的证书链
echo "4. 创建证书链..."
cat device_cert.pem intermediate_ca_cert.pem root_ca_cert.pem > cert_chain.pem

# 7. 生成服务器证书（用于测试）
echo "5. 生成服务器证书..."
openssl genrsa -out server_key.pem 2048
openssl req -new -key server_key.pem -out server_csr.pem \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=TEE Demo/OU=Server/CN=localhost"

cat > server_ext.conf << EOF
[v3_req]
basicConstraints = CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = server.local
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in server_csr.pem -CA intermediate_ca_cert.pem -CAkey intermediate_ca_key.pem \
    -out server_cert.pem -days 365 -extensions v3_req -extfile server_ext.conf \
    -CAcreateserial

# 8. 清理临时文件
rm -f *.csr *.conf *.srl

echo "=== 证书生成完成 ==="
echo "生成的文件："
ls -la *.pem

echo ""
echo "证书链验证："
openssl verify -CAfile root_ca_cert.pem -untrusted intermediate_ca_cert.pem device_cert.pem
openssl verify -CAfile root_ca_cert.pem -untrusted intermediate_ca_cert.pem server_cert.pem

cd ..