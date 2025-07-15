#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// 外部函数声明
extern int tee_provider_configure(const char *cert_path);
extern EVP_PKEY *tee_provider_create_key(OSSL_LIB_CTX *libctx);

int main() {
    printf("=== TEE Provider V3 关键修复验证 ===\n");
    
    // 1. 创建OpenSSL库上下文
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        printf("❌ 无法创建OpenSSL库上下文\n");
        return 1;
    }
    printf("✅ OpenSSL库上下文创建成功\n");
    
    // 2. 加载默认provider
    OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(libctx, "default");
    if (!default_prov) {
        printf("❌ 无法加载默认provider\n");
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    printf("✅ 默认provider加载成功\n");
    
    // 3. 加载TEE Provider V3
    OSSL_PROVIDER *tee_prov = OSSL_PROVIDER_load(libctx, "build/libtee_provider_v3_fix");
    if (!tee_prov) {
        printf("❌ 无法加载TEE Provider V3\n");
        OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    printf("✅ TEE Provider V3加载成功\n");
    
    // 4. 配置TEE Provider
    if (tee_provider_configure("./certs/client.pem") != 1) {
        printf("❌ TEE Provider配置失败\n");
        OSSL_PROVIDER_unload(tee_prov);
        OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    printf("✅ TEE Provider配置成功\n");
    
    // 5. 创建TEE密钥对象
    EVP_PKEY *tee_key = tee_provider_create_key(libctx);
    if (!tee_key) {
        printf("❌ 无法创建TEE密钥\n");
        OSSL_PROVIDER_unload(tee_prov);
        OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    printf("✅ TEE密钥创建成功\n");
    
    // 6. 关键测试：检查私钥能力
    int has_private = EVP_PKEY_can_sign(tee_key);
    printf("🔍 密钥签名能力检查: %s\n", has_private ? "✅ 支持" : "❌ 不支持");
    if (!has_private) {
        printf("❌ 关键错误：密钥不支持签名操作！\n");
        EVP_PKEY_free(tee_key);
        OSSL_PROVIDER_unload(tee_prov);
        OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    
    // 7. 测试密钥大小
    int key_size = EVP_PKEY_bits(tee_key);
    printf("🔍 密钥大小: %d bits\n", key_size);
    
    // 8. 测试密钥类型
    int key_type = EVP_PKEY_base_id(tee_key);
    printf("🔍 密钥类型: %d (RSA=%d)\n", key_type, EVP_PKEY_RSA);
    
    // 9. 关键测试：创建SSL上下文
    printf("🔧 测试SSL上下文创建...\n");
    SSL_CTX *ssl_ctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    if (!ssl_ctx) {
        printf("❌ 无法创建SSL上下文\n");
        EVP_PKEY_free(tee_key);
        OSSL_PROVIDER_unload(tee_prov);
        OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    printf("✅ SSL上下文创建成功\n");
    
    // 10. 关键测试：设置私钥
    printf("🔧 测试设置TEE私钥到SSL上下文...\n");
    if (SSL_CTX_use_PrivateKey(ssl_ctx, tee_key) != 1) {
        printf("❌ 关键错误：无法设置TEE私钥到SSL上下文！\n");
        printf("🔍 OpenSSL错误信息:\n");
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ssl_ctx);
        EVP_PKEY_free(tee_key);
        OSSL_PROVIDER_unload(tee_prov);
        OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    printf("✅ TEE私钥成功设置到SSL上下文！\n");
    
    // 11. 测试证书加载
    printf("🔧 测试加载客户端证书...\n");
    if (SSL_CTX_use_certificate_file(ssl_ctx, "./certs/client.pem", SSL_FILETYPE_PEM) != 1) {
        printf("❌ 无法加载客户端证书\n");
        SSL_CTX_free(ssl_ctx);
        EVP_PKEY_free(tee_key);
        OSSL_PROVIDER_unload(tee_prov);
        OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    printf("✅ 客户端证书加载成功\n");
    
    // 12. 关键测试：检查证书和私钥匹配
    printf("🔧 测试证书和私钥匹配性...\n");
    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        printf("❌ 关键错误：证书和私钥不匹配！\n");
        printf("🔍 OpenSSL错误信息:\n");
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ssl_ctx);
        EVP_PKEY_free(tee_key);
        OSSL_PROVIDER_unload(tee_prov);
        OSSL_PROVIDER_unload(default_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    printf("✅ 证书和TEE私钥匹配性验证通过！\n");
    
    // 清理
    SSL_CTX_free(ssl_ctx);
    EVP_PKEY_free(tee_key);
    OSSL_PROVIDER_unload(tee_prov);
    OSSL_PROVIDER_unload(default_prov);
    OSSL_LIB_CTX_free(libctx);
    
    printf("\n🎉 所有关键测试通过！TEE Provider V3修复成功！\n");
    printf("✅ 密钥签名能力正常\n");
    printf("✅ SSL上下文创建正常\n");
    printf("✅ TEE私钥设置正常\n");
    printf("✅ 证书和私钥匹配正常\n");
    
    return 0;
}