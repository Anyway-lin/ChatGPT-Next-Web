#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#include "tee_provider_v2.h"

void print_errors() {
    unsigned long err;
    char err_buf[256];
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("OpenSSL Error: %s\n", err_buf);
    }
}

int main() {
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_prov = NULL;
    OSSL_PROVIDER *tee_prov = NULL;
    int ret = 0;

    printf("=== TEE Provider V2 简单测试 ===\n");

    // 创建库上下文
    libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        printf("无法创建库上下文\n");
        goto cleanup;
    }
    printf("✓ 库上下文创建成功\n");

    // 加载默认provider
    default_prov = OSSL_PROVIDER_load(libctx, "default");
    if (!default_prov) {
        printf("✗ 无法加载默认provider\n");
        print_errors();
        goto cleanup;
    }
    printf("✓ 默认provider加载成功\n");

    // 添加并加载TEE Provider V2
    extern int OSSL_provider_init(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *, const OSSL_DISPATCH **, void **);
    
    if (OSSL_PROVIDER_add_builtin(libctx, "tee", OSSL_provider_init) == 0) {
        printf("✗ 无法添加TEE Provider V2\n");
        print_errors();
        goto cleanup;
    }
    
    tee_prov = OSSL_PROVIDER_load(libctx, "tee");
    if (!tee_prov) {
        printf("✗ 无法加载TEE Provider V2\n");
        print_errors();
        goto cleanup;
    }
    printf("✓ TEE Provider V2加载成功\n");

    // 配置TEE Provider
    printf("\n--- 配置TEE Provider ---\n");
    if (!tee_provider_configure("./certs/client.pem")) {
        printf("✗ TEE Provider配置失败\n");
        goto cleanup;
    }
    printf("✓ TEE Provider配置成功\n");

    // 测试创建TEE密钥
    printf("\n--- 测试创建TEE密钥 ---\n");
    EVP_PKEY *tee_key = tee_provider_create_key(libctx);
    if (!tee_key) {
        printf("✗ 创建TEE密钥失败\n");
        print_errors();
        goto cleanup;
    }
    printf("✓ TEE密钥创建成功\n");
    
    // 检查密钥信息
    int key_size = EVP_PKEY_bits(tee_key);
    printf("密钥大小: %d bits\n", key_size);
    
    // 清理
    EVP_PKEY_free(tee_key);
    
    ret = 1;

cleanup:
    if (tee_prov) OSSL_PROVIDER_unload(tee_prov);
    if (default_prov) OSSL_PROVIDER_unload(default_prov);
    if (libctx) OSSL_LIB_CTX_free(libctx);

    printf("\n=== 简单测试%s ===\n", ret ? "成功" : "失败");
    return ret ? 0 : 1;
}