#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>

#include "tee_provider.h"

// 错误处理函数
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
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;

    printf("=== TEE Provider 调试测试 ===\n");

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

    // 添加并加载TEE provider
    extern int OSSL_provider_init(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *, const OSSL_DISPATCH **, void **);
    
    if (OSSL_PROVIDER_add_builtin(libctx, "tee", OSSL_provider_init) == 0) {
        printf("✗ 无法添加TEE provider\n");
        print_errors();
        goto cleanup;
    }
    printf("✓ TEE provider添加成功\n");
    
    tee_prov = OSSL_PROVIDER_load(libctx, "tee");
    if (!tee_prov) {
        printf("✗ 无法加载TEE provider\n");
        print_errors();
        goto cleanup;
    }
    printf("✓ TEE provider加载成功\n");

    // 测试：尝试创建默认RSA上下文
    printf("\n--- 测试默认RSA上下文 ---\n");
    ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    if (ctx) {
        printf("✓ 默认RSA上下文创建成功\n");
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    } else {
        printf("✗ 默认RSA上下文创建失败\n");
        print_errors();
    }

    // 测试：尝试创建指定default provider的RSA上下文
    printf("\n--- 测试default provider RSA上下文 ---\n");
    ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", "provider=default");
    if (ctx) {
        printf("✓ default provider RSA上下文创建成功\n");
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    } else {
        printf("✗ default provider RSA上下文创建失败\n");
        print_errors();
    }

    // 测试：尝试创建TEE provider的RSA上下文
    printf("\n--- 测试TEE provider RSA上下文 ---\n");
    ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", "provider=tee");
    if (ctx) {
        printf("✓ TEE provider RSA上下文创建成功\n");
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    } else {
        printf("✗ TEE provider RSA上下文创建失败\n");
        print_errors();
    }

    // 测试：检查可用的providers
    printf("\n--- 检查可用的providers ---\n");
    OSSL_PROVIDER *prov;
    prov = OSSL_PROVIDER_load(libctx, "default");
    if (prov) {
        printf("✓ default provider 可用\n");
        OSSL_PROVIDER_unload(prov);
    }
    
    prov = OSSL_PROVIDER_load(libctx, "tee");
    if (prov) {
        printf("✓ tee provider 可用\n");
        OSSL_PROVIDER_unload(prov);
    }

    // 测试：尝试获取算法
    printf("\n--- 测试算法获取 ---\n");
    EVP_SIGNATURE *sig_alg = EVP_SIGNATURE_fetch(libctx, "RSA", "provider=tee");
    if (sig_alg) {
        printf("✓ TEE RSA签名算法获取成功\n");
        EVP_SIGNATURE_free(sig_alg);
    } else {
        printf("✗ TEE RSA签名算法获取失败\n");
        print_errors();
    }

    EVP_KEYMGMT *keymgmt = EVP_KEYMGMT_fetch(libctx, "RSA", "provider=tee");
    if (keymgmt) {
        printf("✓ TEE RSA密钥管理算法获取成功\n");
        EVP_KEYMGMT_free(keymgmt);
    } else {
        printf("✗ TEE RSA密钥管理算法获取失败\n");
        print_errors();
    }

    ret = 1;

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (tee_prov) OSSL_PROVIDER_unload(tee_prov);
    if (default_prov) OSSL_PROVIDER_unload(default_prov);
    if (libctx) OSSL_LIB_CTX_free(libctx);

    printf("\n=== 调试测试完成 ===\n");
    return ret ? 0 : 1;
}