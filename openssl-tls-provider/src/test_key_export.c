#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

int main() {
    printf("=== TEE Provider 密钥导出测试 ===\n");
    
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        printf("❌ 无法创建OpenSSL库上下文\n");
        return 1;
    }
    
    // 加载TEE Provider
    OSSL_PROVIDER *tee_prov = OSSL_PROVIDER_load(libctx, "tee_provider_v2");
    if (!tee_prov) {
        printf("❌ 无法加载TEE Provider V2\n");
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    printf("✅ TEE Provider V2加载成功\n");
    
    // 配置TEE Provider
    extern int tee_provider_configure(const char *cert_path);
    if (tee_provider_configure("./certs/client.pem") != 1) {
        printf("❌ TEE Provider配置失败\n");
        OSSL_PROVIDER_unload(tee_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    printf("✅ TEE Provider配置成功\n");
    
    // 创建TEE密钥
    extern EVP_PKEY *tee_provider_create_key(OSSL_LIB_CTX *libctx);
    EVP_PKEY *tee_key = tee_provider_create_key(libctx);
    if (!tee_key) {
        printf("❌ 无法创建TEE密钥\n");
        OSSL_PROVIDER_unload(tee_prov);
        OSSL_LIB_CTX_free(libctx);
        return 1;
    }
    printf("✅ TEE密钥创建成功\n");
    
    // 测试私钥能力检查
    int has_private = EVP_PKEY_can_sign(tee_key);
    printf("🔍 密钥签名能力检查: %s\n", has_private ? "支持" : "不支持");
    
    // 测试密钥大小
    int key_size = EVP_PKEY_bits(tee_key);
    printf("🔍 密钥大小: %d bits\n", key_size);
    
    // 测试密钥类型
    int key_type = EVP_PKEY_base_id(tee_key);
    printf("🔍 密钥类型: %d (RSA=%d)\n", key_type, EVP_PKEY_RSA);
    
    // 清理
    EVP_PKEY_free(tee_key);
    OSSL_PROVIDER_unload(tee_prov);
    OSSL_LIB_CTX_free(libctx);
    
    printf("✅ 密钥导出测试完成\n");
    return 0;
}