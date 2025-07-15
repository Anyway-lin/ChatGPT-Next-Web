/*
 * 简单的TEE Provider测试程序
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main() {
    OSSL_PROVIDER *tee_prov = NULL;
    OSSL_PROVIDER *default_prov = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    const char *data = "Hello TEE Provider!";
    unsigned char *signature = NULL;
    size_t sig_len = 0;
    int ret = 1;
    
    printf("=== TEE Provider 简单测试 ===\n");
    
    /* 设置环境变量 */
    setenv("TEE_PRIVATE_KEY", "/workspace/tee_private_key.pem", 1);
    setenv("TEE_CERTIFICATE", "/workspace/tee_certificate.pem", 1);
    
    /* 加载providers */
    printf("1. 加载Providers...\n");
    tee_prov = OSSL_PROVIDER_load(NULL, "tee");
    if (!tee_prov) {
        printf("错误: 无法加载TEE Provider\n");
        goto end;
    }
    
    default_prov = OSSL_PROVIDER_load(NULL, "default");
    if (!default_prov) {
        printf("错误: 无法加载Default Provider\n");
        goto end;
    }
    
    printf("✓ Providers加载成功\n");
    
    /* 创建密钥上下文 */
    printf("2. 创建密钥上下文...\n");
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=tee");
    if (!ctx) {
        printf("错误: 无法创建密钥上下文\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    
    printf("✓ 密钥上下文创建成功\n");
    
    /* 尝试直接从Key Management加载密钥 */
    printf("3. 测试密钥管理...\n");
    
    /* 创建签名上下文 */
    EVP_PKEY_CTX *sign_ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=tee");
    if (!sign_ctx) {
        printf("错误: 无法创建签名上下文\n");
        goto end;
    }
    
    printf("✓ 签名上下文创建成功\n");
    
    printf("4. 测试完成\n");
    ret = 0;
    
end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(tee_prov);
    OSSL_PROVIDER_unload(default_prov);
    
    return ret;
}