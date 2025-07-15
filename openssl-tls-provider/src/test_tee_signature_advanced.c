#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "tee_provider.h"

// 错误处理函数
void print_openssl_errors() {
    unsigned long err;
    char err_buf[256];
    
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("OpenSSL Error: %s\n", err_buf);
    }
}

// 测试TEE provider的签名功能
int test_tee_signature() {
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_prov = NULL;
    OSSL_PROVIDER *tee_prov = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    const char *data = "Hello, TEE Provider!";
    unsigned char *sig = NULL;
    size_t siglen = 0;
    int ret = 0;

    printf("=== TEE Provider 高级签名测试 ===\n");

    // 创建库上下文
    libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        printf("无法创建库上下文\n");
        goto cleanup;
    }

    // 加载默认provider
    default_prov = OSSL_PROVIDER_load(libctx, "default");
    if (!default_prov) {
        printf("无法加载默认provider\n");
        goto cleanup;
    }

    // 添加并加载TEE provider
    extern int OSSL_provider_init(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *, const OSSL_DISPATCH **, void **);
    
    if (OSSL_PROVIDER_add_builtin(libctx, "tee", OSSL_provider_init) == 0) {
        printf("无法添加TEE provider\n");
        goto cleanup;
    }
    
    tee_prov = OSSL_PROVIDER_load(libctx, "tee");
    if (!tee_prov) {
        printf("无法加载TEE provider\n");
        goto cleanup;
    }

    printf("TEE Provider 加载成功\n");

    // 设置证书路径并构建TEE私钥
    tee_provider_set_certificate_path("./certs/client.pem");
    printf("TEE 私钥构建完成\n");

    // 获取TEE私钥
    pkey = tee_provider_get_private_key();
    if (!pkey) {
        printf("无法获取TEE私钥\n");
        goto cleanup;
    }

    printf("成功获取TEE私钥\n");

    // 创建签名上下文，明确指定使用TEE provider
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, "provider=tee");
    if (!ctx) {
        printf("无法创建签名上下文\n");
        print_openssl_errors();
        goto cleanup;
    }

    printf("签名上下文创建成功\n");

    // 初始化签名操作
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        printf("签名初始化失败\n");
        print_openssl_errors();
        goto cleanup;
    }

    printf("签名初始化成功\n");

    // 获取签名长度
    if (EVP_PKEY_sign(ctx, NULL, &siglen, (const unsigned char*)data, strlen(data)) <= 0) {
        printf("获取签名长度失败\n");
        print_openssl_errors();
        goto cleanup;
    }

    printf("签名长度: %zu 字节\n", siglen);

    // 分配签名缓冲区
    sig = OPENSSL_malloc(siglen);
    if (!sig) {
        printf("内存分配失败\n");
        goto cleanup;
    }

    // 执行签名
    printf("开始执行签名...\n");
    if (EVP_PKEY_sign(ctx, sig, &siglen, (const unsigned char*)data, strlen(data)) <= 0) {
        printf("签名操作失败\n");
        print_openssl_errors();
        goto cleanup;
    }

    printf("TEE 签名成功！签名长度: %zu 字节\n", siglen);
    printf("签名数据 (前32字节): ");
    for (size_t i = 0; i < (siglen < 32 ? siglen : 32); i++) {
        printf("%02x", sig[i]);
    }
    printf("\n");

    ret = 1;

cleanup:
    if (sig) OPENSSL_free(sig);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (tee_prov) OSSL_PROVIDER_unload(tee_prov);
    if (default_prov) OSSL_PROVIDER_unload(default_prov);
    if (libctx) OSSL_LIB_CTX_free(libctx);

    return ret;
}

// 测试使用摘要的签名操作
int test_tee_digest_signature() {
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_prov = NULL;
    OSSL_PROVIDER *tee_prov = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    const char *data = "Hello, TEE Provider with Digest!";
    unsigned char *sig = NULL;
    size_t siglen = 0;
    int ret = 0;

    printf("\n=== TEE Provider 摘要签名测试 ===\n");

    // 创建库上下文
    libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        printf("无法创建库上下文\n");
        goto cleanup;
    }

    // 加载默认provider
    default_prov = OSSL_PROVIDER_load(libctx, "default");
    if (!default_prov) {
        printf("无法加载默认provider\n");
        goto cleanup;
    }

    // 添加并加载TEE provider
    extern int OSSL_provider_init(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *, const OSSL_DISPATCH **, void **);
    
    if (OSSL_PROVIDER_add_builtin(libctx, "tee", OSSL_provider_init) == 0) {
        printf("无法添加TEE provider\n");
        goto cleanup;
    }
    
    tee_prov = OSSL_PROVIDER_load(libctx, "tee");
    if (!tee_prov) {
        printf("无法加载TEE provider\n");
        goto cleanup;
    }

    printf("TEE Provider 加载成功\n");

    // 设置证书路径并构建TEE私钥
    tee_provider_set_certificate_path("./certs/client.pem");

    // 获取TEE私钥
    pkey = tee_provider_get_private_key();
    if (!pkey) {
        printf("无法获取TEE私钥\n");
        goto cleanup;
    }

    printf("成功获取TEE私钥\n");

    // 创建摘要上下文
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        printf("无法创建摘要上下文\n");
        goto cleanup;
    }

    printf("摘要上下文创建成功\n");

    // 初始化摘要签名，明确指定使用SHA256和TEE provider
    if (EVP_DigestSignInit_ex(mdctx, NULL, "SHA256", libctx, "provider=tee", pkey, NULL) <= 0) {
        printf("摘要签名初始化失败\n");
        print_openssl_errors();
        goto cleanup;
    }

    printf("摘要签名初始化成功\n");

    // 更新数据
    if (EVP_DigestSignUpdate(mdctx, data, strlen(data)) <= 0) {
        printf("摘要签名更新失败\n");
        print_openssl_errors();
        goto cleanup;
    }

    printf("摘要签名数据更新成功\n");

    // 获取签名长度
    if (EVP_DigestSignFinal(mdctx, NULL, &siglen) <= 0) {
        printf("获取摘要签名长度失败\n");
        print_openssl_errors();
        goto cleanup;
    }

    printf("摘要签名长度: %zu 字节\n", siglen);

    // 分配签名缓冲区
    sig = OPENSSL_malloc(siglen);
    if (!sig) {
        printf("内存分配失败\n");
        goto cleanup;
    }

    // 执行摘要签名
    printf("开始执行摘要签名...\n");
    if (EVP_DigestSignFinal(mdctx, sig, &siglen) <= 0) {
        printf("摘要签名操作失败\n");
        print_openssl_errors();
        goto cleanup;
    }

    printf("TEE 摘要签名成功！签名长度: %zu 字节\n", siglen);
    printf("签名数据 (前32字节): ");
    for (size_t i = 0; i < (siglen < 32 ? siglen : 32); i++) {
        printf("%02x", sig[i]);
    }
    printf("\n");

    ret = 1;

cleanup:
    if (sig) OPENSSL_free(sig);
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (tee_prov) OSSL_PROVIDER_unload(tee_prov);
    if (default_prov) OSSL_PROVIDER_unload(default_prov);
    if (libctx) OSSL_LIB_CTX_free(libctx);

    return ret;
}

int main() {
    printf("开始TEE Provider高级签名测试...\n\n");

    // 测试直接签名
    if (!test_tee_signature()) {
        printf("直接签名测试失败\n");
        return 1;
    }

    // 测试摘要签名
    if (!test_tee_digest_signature()) {
        printf("摘要签名测试失败\n");
        return 1;
    }

    printf("\n=== 所有TEE Provider签名测试通过！ ===\n");
    return 0;
}