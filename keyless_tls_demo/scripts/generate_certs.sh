#!/bin/bash

# Certificate Generation Script for Keyless TLS Demo
# This script generates a certificate chain: Root CA -> Intermediate CA -> Device Certificate

set -e

CERTS_DIR="../certs"
mkdir -p $CERTS_DIR

echo "Generating certificate chain for keyless TLS demo..."

# 1. Generate Root CA private key and certificate
echo "1. Generating Root CA..."
openssl genrsa -out $CERTS_DIR/root_ca_key.pem 4096
openssl req -new -x509 -days 3650 -key $CERTS_DIR/root_ca_key.pem \
    -out $CERTS_DIR/root_ca_cert.pem \
    -subj "/C=CN/ST=BJ/L=Beijing/O=TrustRoot/OU=Security/CN=Root CA"

# 2. Generate Intermediate CA private key and certificate
echo "2. Generating Intermediate CA..."
openssl genrsa -out $CERTS_DIR/intermediate_ca_key.pem 4096
openssl req -new -key $CERTS_DIR/intermediate_ca_key.pem \
    -out $CERTS_DIR/intermediate_ca_csr.pem \
    -subj "/C=CN/ST=BJ/L=Beijing/O=TrustRoot/OU=Security/CN=Intermediate CA"

# Sign intermediate CA with root CA
openssl x509 -req -days 1825 -in $CERTS_DIR/intermediate_ca_csr.pem \
    -CA $CERTS_DIR/root_ca_cert.pem -CAkey $CERTS_DIR/root_ca_key.pem \
    -CAcreateserial -out $CERTS_DIR/intermediate_ca_cert.pem \
    -extensions v3_ca -extfile <(cat <<EOF
[v3_ca]
basicConstraints = CA:true
keyUsage = digitalSignature, keyEncipherment, keyCertSign
EOF
)

# 3. Generate Device Certificate (this will be used for TEE keyless operations)
echo "3. Generating Device Certificate..."
openssl genrsa -out $CERTS_DIR/device_key.pem 2048
openssl req -new -key $CERTS_DIR/device_key.pem \
    -out $CERTS_DIR/device_csr.pem \
    -subj "/C=CN/ST=BJ/L=Beijing/O=TrustRoot/OU=Device/CN=device.example.com"

# Sign device certificate with intermediate CA
openssl x509 -req -days 365 -in $CERTS_DIR/device_csr.pem \
    -CA $CERTS_DIR/intermediate_ca_cert.pem -CAkey $CERTS_DIR/intermediate_ca_key.pem \
    -CAcreateserial -out $CERTS_DIR/device_cert.pem \
    -extensions v3_req -extfile <(cat <<EOF
[v3_req]
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = device.example.com
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
)

# 4. Create certificate chain file (device + intermediate + root)
echo "4. Creating certificate chain..."
cat $CERTS_DIR/device_cert.pem > $CERTS_DIR/device_chain.pem
cat $CERTS_DIR/intermediate_ca_cert.pem >> $CERTS_DIR/device_chain.pem
cat $CERTS_DIR/root_ca_cert.pem >> $CERTS_DIR/device_chain.pem

# 5. Generate server certificate for testing
echo "5. Generating server certificate for testing..."
openssl genrsa -out $CERTS_DIR/server_key.pem 2048
openssl req -new -key $CERTS_DIR/server_key.pem \
    -out $CERTS_DIR/server_csr.pem \
    -subj "/C=CN/ST=BJ/L=Beijing/O=TrustRoot/OU=Server/CN=server.example.com"

openssl x509 -req -days 365 -in $CERTS_DIR/server_csr.pem \
    -CA $CERTS_DIR/intermediate_ca_cert.pem -CAkey $CERTS_DIR/intermediate_ca_key.pem \
    -CAcreateserial -out $CERTS_DIR/server_cert.pem \
    -extensions v3_req -extfile <(cat <<EOF
[v3_req]
basicConstraints = CA:false
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = server.example.com
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
)

# Clean up CSR files
rm -f $CERTS_DIR/*.csr $CERTS_DIR/*.srl

echo "Certificate generation completed!"
echo "Generated files:"
echo "  - Root CA: $CERTS_DIR/root_ca_cert.pem"
echo "  - Intermediate CA: $CERTS_DIR/intermediate_ca_cert.pem"  
echo "  - Device Certificate: $CERTS_DIR/device_cert.pem"
echo "  - Device Chain: $CERTS_DIR/device_chain.pem"
echo "  - Server Certificate: $CERTS_DIR/server_cert.pem"
echo "  - Device Private Key: $CERTS_DIR/device_key.pem (for TEE simulation)"