#!/bin/bash

# TEE Provider 测试证书生成脚本
# 生成完整的证书链：根证书 -> 中间证书 -> 设备证书

set -e

echo "=========================================="
echo "TEE Provider 测试证书生成脚本"
echo "=========================================="

# 清理之前的文件
echo "清理之前的证书文件..."
rm -f *.pem *.csr *.crt *.srl *.key

# 1. 生成根CA私钥和证书
echo "1. 生成根CA证书..."
openssl genpkey -algorithm RSA -out root_ca_key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key root_ca_key.pem -out root_ca_cert.pem -days 3650 \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=TEE Test Root CA/CN=TEE Root CA"

echo "根CA证书生成完成: root_ca_cert.pem"

# 2. 生成中间CA私钥和证书
echo "2. 生成中间CA证书..."
openssl genpkey -algorithm RSA -out intermediate_ca_key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -key intermediate_ca_key.pem -out intermediate_ca.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=TEE Test Intermediate CA/CN=TEE Intermediate CA"

# 创建中间CA证书扩展配置
cat > intermediate_ca_ext.cnf << EOF
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

openssl x509 -req -in intermediate_ca.csr -CA root_ca_cert.pem -CAkey root_ca_key.pem \
    -out intermediate_ca_cert.pem -days 1825 -CAcreateserial \
    -extfile intermediate_ca_ext.cnf

echo "中间CA证书生成完成: intermediate_ca_cert.pem"

# 3. 生成设备私钥和证书 (这个私钥将模拟存储在TEE中)
echo "3. 生成设备证书和私钥..."
openssl genpkey -algorithm RSA -out tee_private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -key tee_private_key.pem -out device.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=TEE Test Device/CN=TEE Device 001"

# 创建设备证书扩展配置
cat > device_ext.cnf << EOF
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
subjectAltName = @alt_names

[alt_names]
DNS.1 = tee-device.local
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in device.csr -CA intermediate_ca_cert.pem -CAkey intermediate_ca_key.pem \
    -out tee_certificate.pem -days 365 -CAcreateserial \
    -extfile device_ext.cnf

echo "设备证书生成完成: tee_certificate.pem"

# 4. 创建完整的证书链文件
echo "4. 创建证书链文件..."
cat tee_certificate.pem intermediate_ca_cert.pem root_ca_cert.pem > tee_cert_chain.pem
echo "证书链文件生成完成: tee_cert_chain.pem"

# 5. 生成EC密钥对用于测试ECDSA
echo "5. 生成EC密钥对..."
openssl genpkey -algorithm EC -out tee_ec_private_key.pem \
    -pkeyopt ec_paramgen_curve:P-256
openssl req -new -key tee_ec_private_key.pem -out device_ec.csr \
    -subj "/C=CN/ST=Beijing/L=Beijing/O=TEE Test Device EC/CN=TEE Device EC 001"

openssl x509 -req -in device_ec.csr -CA intermediate_ca_cert.pem -CAkey intermediate_ca_key.pem \
    -out tee_ec_certificate.pem -days 365 -CAcreateserial \
    -extfile device_ext.cnf

echo "EC设备证书生成完成: tee_ec_certificate.pem"

# 6. 验证证书链
echo "6. 验证证书链..."
openssl verify -CAfile root_ca_cert.pem -untrusted intermediate_ca_cert.pem tee_certificate.pem
openssl verify -CAfile root_ca_cert.pem -untrusted intermediate_ca_cert.pem tee_ec_certificate.pem

# 7. 显示证书信息
echo "7. 证书信息摘要..."
echo ""
echo "根CA证书:"
openssl x509 -in root_ca_cert.pem -subject -issuer -dates -noout

echo ""
echo "中间CA证书:"
openssl x509 -in intermediate_ca_cert.pem -subject -issuer -dates -noout

echo ""
echo "设备证书 (RSA):"
openssl x509 -in tee_certificate.pem -subject -issuer -dates -noout

echo ""
echo "设备证书 (EC):"
openssl x509 -in tee_ec_certificate.pem -subject -issuer -dates -noout

# 8. 清理临时文件
echo ""
echo "8. 清理临时文件..."
rm -f *.csr *.srl intermediate_ca_ext.cnf device_ext.cnf

# 9. 设置权限
echo "9. 设置文件权限..."
chmod 600 *_key.pem
chmod 644 *.pem

echo ""
echo "=========================================="
echo "证书生成完成！生成的文件："
echo "=========================================="
echo "根证书:           root_ca_cert.pem"
echo "中间证书:         intermediate_ca_cert.pem"
echo "设备证书(RSA):    tee_certificate.pem"
echo "设备证书(EC):     tee_ec_certificate.pem"
echo "证书链:           tee_cert_chain.pem"
echo "TEE私钥(RSA):     tee_private_key.pem"
echo "TEE私钥(EC):      tee_ec_private_key.pem"
echo ""
echo "环境变量设置："
echo "export TEE_PRIVATE_KEY=$(pwd)/tee_private_key.pem"
echo "export TEE_CERTIFICATE=$(pwd)/tee_certificate.pem"
echo "export TEE_EC_PRIVATE_KEY=$(pwd)/tee_ec_private_key.pem"
echo "export TEE_EC_CERTIFICATE=$(pwd)/tee_ec_certificate.pem"
echo "=========================================="