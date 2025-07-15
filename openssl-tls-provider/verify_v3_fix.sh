#!/bin/bash

echo "============================================"
echo "🎯 TEE Provider V3 关键修复验证脚本"
echo "============================================"

# 设置颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 错误处理函数
error_exit() {
    echo -e "${RED}❌ 错误: $1${NC}"
    exit 1
}

success_msg() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning_msg() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

info_msg() {
    echo -e "${BLUE}🔍 $1${NC}"
}

# 检查依赖
echo "1. 检查系统依赖..."
command -v gcc >/dev/null 2>&1 || error_exit "gcc 编译器未安装"
command -v openssl >/dev/null 2>&1 || error_exit "OpenSSL 命令行工具未安装"
command -v pkg-config >/dev/null 2>&1 || error_exit "pkg-config 未安装"

# 检查OpenSSL开发库
pkg-config --exists openssl || error_exit "OpenSSL 开发库未安装"
success_msg "系统依赖检查完成"

# 2. 清理和准备
echo ""
echo "2. 清理之前的构建..."
make -f Makefile_v3 clean-all >/dev/null 2>&1
success_msg "清理完成"

# 3. 生成证书
echo ""
echo "3. 生成测试证书..."
make -f Makefile_v3 certs >/dev/null 2>&1 || error_exit "证书生成失败"
success_msg "测试证书生成完成"

# 4. 编译TEE Provider V3
echo ""
echo "4. 编译TEE Provider V3..."
make -f Makefile_v3 all || error_exit "编译失败"
success_msg "TEE Provider V3编译成功"

# 5. 运行关键修复验证
echo ""
echo "5. 运行关键修复验证..."
info_msg "这个测试将验证以下关键功能："
info_msg "  - TEE Provider加载"
info_msg "  - 密钥签名能力检查"
info_msg "  - SSL上下文创建"
info_msg "  - TEE私钥设置"
info_msg "  - 证书和私钥匹配性"

echo ""
echo "🚀 开始验证测试..."
export LD_LIBRARY_PATH=build:$LD_LIBRARY_PATH

# 运行测试并捕获输出
TEST_OUTPUT=$(./build/test_v3_simple 2>&1)
TEST_RESULT=$?

echo "$TEST_OUTPUT"

if [ $TEST_RESULT -eq 0 ]; then
    success_msg "关键修复验证测试通过！"
    
    # 检查关键成功指标
    echo ""
    echo "6. 验证关键成功指标..."
    
    if echo "$TEST_OUTPUT" | grep -q "密钥签名能力检查: ✅ 支持"; then
        success_msg "密钥签名能力检查通过"
    else
        error_exit "密钥签名能力检查失败"
    fi
    
    if echo "$TEST_OUTPUT" | grep -q "TEE私钥成功设置到SSL上下文"; then
        success_msg "TEE私钥设置到SSL上下文成功"
    else
        error_exit "TEE私钥设置到SSL上下文失败"
    fi
    
    if echo "$TEST_OUTPUT" | grep -q "证书和TEE私钥匹配性验证通过"; then
        success_msg "证书和私钥匹配性验证通过"
    else
        error_exit "证书和私钥匹配性验证失败"
    fi
    
    if echo "$TEST_OUTPUT" | grep -q "所有关键测试通过"; then
        success_msg "所有关键测试通过"
    else
        error_exit "关键测试未全部通过"
    fi
    
else
    error_exit "关键修复验证测试失败"
fi

# 7. 创建完整的TLS客户端测试（可选）
echo ""
echo "7. 准备完整TLS测试环境..."

# 创建完整的TLS客户端
cat > src/tls_client_v3.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>

// 外部函数声明
extern int tee_provider_configure(const char *cert_path);
extern EVP_PKEY *tee_provider_create_key(OSSL_LIB_CTX *libctx);

int main() {
    printf("=== TEE Provider V3 完整TLS客户端测试 ===\n");
    
    // 创建OpenSSL库上下文
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        printf("❌ 无法创建OpenSSL库上下文\n");
        return 1;
    }
    
    // 加载providers
    OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(libctx, "default");
    OSSL_PROVIDER *tee_prov = OSSL_PROVIDER_load(libctx, "build/libtee_provider_v3_fix");
    
    if (!default_prov || !tee_prov) {
        printf("❌ 无法加载providers\n");
        return 1;
    }
    printf("✅ Providers加载成功\n");
    
    // 配置TEE Provider
    if (tee_provider_configure("./certs/client.pem") != 1) {
        printf("❌ TEE Provider配置失败\n");
        return 1;
    }
    printf("✅ TEE Provider配置成功\n");
    
    // 创建SSL上下文
    SSL_CTX *ctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    if (!ctx) {
        printf("❌ 无法创建SSL上下文\n");
        return 1;
    }
    printf("✅ SSL上下文创建成功\n");
    
    // 加载CA证书
    if (SSL_CTX_load_verify_locations(ctx, "./certs/ca.pem", NULL) != 1) {
        printf("❌ 无法加载CA证书\n");
        return 1;
    }
    printf("✅ CA证书加载成功\n");
    
    // 加载客户端证书
    if (SSL_CTX_use_certificate_file(ctx, "./certs/client.pem", SSL_FILETYPE_PEM) != 1) {
        printf("❌ 无法加载客户端证书\n");
        return 1;
    }
    printf("✅ 客户端证书加载成功\n");
    
    // 关键测试：设置TEE私钥
    printf("🔑 设置TEE私钥...\n");
    EVP_PKEY *tee_key = tee_provider_create_key(libctx);
    if (!tee_key) {
        printf("❌ 无法创建TEE密钥\n");
        return 1;
    }
    
    if (SSL_CTX_use_PrivateKey(ctx, tee_key) != 1) {
        printf("❌ 关键错误：无法设置TEE私钥！\n");
        printf("OpenSSL错误:\n");
        ERR_print_errors_fp(stdout);
        return 1;
    }
    printf("✅ TEE私钥设置成功\n");
    
    // 验证证书和私钥匹配
    if (SSL_CTX_check_private_key(ctx) != 1) {
        printf("❌ 证书和私钥不匹配！\n");
        printf("OpenSSL错误:\n");
        ERR_print_errors_fp(stdout);
        return 1;
    }
    printf("✅ 证书和TEE私钥匹配验证通过\n");
    
    // 设置验证模式
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    printf("\n🎉 TEE Provider V3 TLS客户端准备就绪！\n");
    printf("✅ 所有关键组件配置成功\n");
    printf("✅ 'missing private key' 错误已解决\n");
    printf("✅ 证书和TEE私钥匹配正常\n");
    printf("ℹ️  客户端现在可以进行TLS握手（需要对应的服务器）\n");
    
    // 清理
    EVP_PKEY_free(tee_key);
    SSL_CTX_free(ctx);
    OSSL_PROVIDER_unload(tee_prov);
    OSSL_PROVIDER_unload(default_prov);
    OSSL_LIB_CTX_free(libctx);
    
    return 0;
}
EOF

# 编译完整TLS客户端
echo "编译完整TLS客户端..."
gcc -Wall -g -o build/tls_client_v3 src/tls_client_v3.c -Lbuild -ltee_provider_v3_fix -lssl -lcrypto || error_exit "TLS客户端编译失败"
success_msg "完整TLS客户端编译成功"

# 8. 运行完整TLS客户端测试
echo ""
echo "8. 运行完整TLS客户端测试..."
export LD_LIBRARY_PATH=build:$LD_LIBRARY_PATH
./build/tls_client_v3 || error_exit "完整TLS客户端测试失败"

echo ""
echo "============================================"
echo "🎉 TEE Provider V3 修复验证完成！"
echo "============================================"
success_msg "基础功能测试：通过"
success_msg "关键修复验证：通过"
success_msg "SSL上下文创建：通过"
success_msg "TEE私钥设置：通过"
success_msg "证书匹配验证：通过"
success_msg "完整TLS客户端：就绪"

echo ""
warning_msg "注意事项："
echo "  1. 这个修复解决了 'missing private key' 错误"
echo "  2. TEE私钥通过虚拟指示器方式提供给OpenSSL"
echo "  3. 实际私钥操作仍然在TEE中执行"
echo "  4. 可以进行完整的TLS握手（需要对应服务器）"

echo ""
info_msg "下一步："
echo "  - 将 src/tee_provider_v3_fix.c 替换您的原始实现"
echo "  - 使用 build/tls_client_v3 进行实际TLS连接测试"
echo "  - 集成到您的生产环境中"

echo ""
success_msg "验证脚本执行完成！"