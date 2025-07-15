#!/bin/bash

# 证书生成脚本 - TEE Provider 测试证书
# 本脚本生成完整的证书链：根证书 -> 中间证书 -> 设备证书/服务器证书

set -e

echo "=== TEE Provider Certificate Generation ==="

# 清理旧文件
rm -f *.pem *.key *.csr *.srl

# 证书有效期
DAYS=365
KEY_SIZE=2048

echo "Step 1: Generating Root CA..."

# 1. 生成根CA私钥
openssl genrsa -out root_key.pem $KEY_SIZE
echo "Generated root CA private key"

# 2. 生成根CA证书
openssl req -new -x509 -key root_key.pem -out root_cert.pem -days $DAYS -subj "/C=CN/O=TEE Provider/OU=Root CA/CN=TEE Root CA"
echo "Generated root CA certificate"

echo "Step 2: Generating Intermediate CA..."

# 3. 生成中间CA私钥
openssl genrsa -out intermediate_key.pem $KEY_SIZE
echo "Generated intermediate CA private key"

# 4. 生成中间CA证书请求
openssl req -new -key intermediate_key.pem -out intermediate.csr -subj "/C=CN/O=TEE Provider/OU=Intermediate CA/CN=TEE Intermediate CA"
echo "Generated intermediate CA certificate request"

# 5. 用根CA签发中间CA证书
cat > intermediate_ext.cnf << EOF
basicConstraints = CA:true
keyUsage = keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF

openssl x509 -req -in intermediate.csr -CA root_cert.pem -CAkey root_key.pem -CAcreateserial -out intermediate_cert.pem -days $DAYS -extensions v3_ca -extfile intermediate_ext.cnf
echo "Generated intermediate CA certificate"

echo "Step 3: Generating Device Certificate..."

# 6. 生成设备私钥 (这个私钥将在TEE中模拟)
openssl genrsa -out device_key.pem $KEY_SIZE
echo "Generated device private key"

# 7. 生成设备证书请求
openssl req -new -key device_key.pem -out device.csr -subj "/C=CN/O=TEE Provider/OU=Device/CN=TEE Device"
echo "Generated device certificate request"

# 8. 用中间CA签发设备证书
cat > device_ext.cnf << EOF
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
subjectAltName = @alt_names

[alt_names]
DNS.1 = tee-device
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in device.csr -CA intermediate_cert.pem -CAkey intermediate_key.pem -CAcreateserial -out device_cert.pem -days $DAYS -extensions v3_req -extfile device_ext.cnf
echo "Generated device certificate"

echo "Step 4: Generating Server Certificate..."

# 9. 生成服务器私钥
openssl genrsa -out server_key.pem $KEY_SIZE
echo "Generated server private key"

# 10. 生成服务器证书请求
openssl req -new -key server_key.pem -out server.csr -subj "/C=CN/O=TEE Provider/OU=Server/CN=TEE Server"
echo "Generated server certificate request"

# 11. 用中间CA签发服务器证书
cat > server_ext.cnf << EOF
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
subjectAltName = @alt_names

[alt_names]
DNS.1 = tee-server
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in server.csr -CA intermediate_cert.pem -CAkey intermediate_key.pem -CAcreateserial -out server_cert.pem -days $DAYS -extensions v3_req -extfile server_ext.cnf
echo "Generated server certificate"

echo "Step 5: Creating Certificate Chains..."

# 12. 创建完整的证书链文件
cat device_cert.pem intermediate_cert.pem root_cert.pem > device_chain.pem
echo "Created device certificate chain"

cat server_cert.pem intermediate_cert.pem root_cert.pem > server_chain.pem
echo "Created server certificate chain"

echo "Step 6: Creating Trust Store..."

# 13. 创建信任存储（包含根证书和中间证书）
cat root_cert.pem intermediate_cert.pem > ca_bundle.pem
echo "Created CA bundle"

echo "Step 7: Verification..."

# 14. 验证证书链
echo "Verifying device certificate chain..."
openssl verify -CAfile ca_bundle.pem device_cert.pem
if [ $? -eq 0 ]; then
    echo "✓ Device certificate chain verification passed"
else
    echo "✗ Device certificate chain verification failed"
fi

echo "Verifying server certificate chain..."
openssl verify -CAfile ca_bundle.pem server_cert.pem
if [ $? -eq 0 ]; then
    echo "✓ Server certificate chain verification passed"
else
    echo "✗ Server certificate chain verification failed"
fi

echo "Step 8: Displaying Certificate Information..."

# 15. 显示证书信息
echo ""
echo "=== Root Certificate Info ==="
openssl x509 -in root_cert.pem -text -noout | grep -A 5 "Subject:"

echo ""
echo "=== Intermediate Certificate Info ==="
openssl x509 -in intermediate_cert.pem -text -noout | grep -A 5 "Subject:"

echo ""
echo "=== Device Certificate Info ==="
openssl x509 -in device_cert.pem -text -noout | grep -A 5 "Subject:"

echo ""
echo "=== Server Certificate Info ==="
openssl x509 -in server_cert.pem -text -noout | grep -A 5 "Subject:"

# 16. 清理临时文件
rm -f *.csr *.srl *.cnf

echo ""
echo "=== Certificate Generation Complete ==="
echo "Generated files:"
echo "  Root CA:          root_cert.pem, root_key.pem"
echo "  Intermediate CA:  intermediate_cert.pem, intermediate_key.pem"
echo "  Device:           device_cert.pem, device_key.pem"
echo "  Server:           server_cert.pem, server_key.pem"
echo "  Certificate chains: device_chain.pem, server_chain.pem"
echo "  CA bundle:        ca_bundle.pem"
echo ""
echo "Note: In real TEE environment, device_key.pem should be stored in TEE"
echo "      and never exposed to the host application."
echo ""

# 17. 设置文件权限
chmod 600 *.pem
echo "Set secure file permissions for all certificate files"

echo "All certificates generated successfully!"