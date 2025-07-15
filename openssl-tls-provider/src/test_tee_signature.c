#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include "tee_provider.h"

// 测试数据
static const char test_data[] = "Hello, TEE Provider! This is a test message for signing.";

// 错误处理函数
void handle_error(const char *msg) {
    unsigned long err;
    char err_buf[256];
    
    printf("[ERROR] %s\n", msg);
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        printf("OpenSSL Error: %s\n", err_buf);
    }
}

int main() {
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_prov = NULL;
    OSSL_PROVIDER *tee_prov = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char *signature = NULL;
    size_t sig_len = 0;
    int ret = 1;
    
    printf("=== TEE Provider 签名测试 ===\n");
    
    // 创建库上下文
    libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        handle_error("无法创建库上下文");
        goto cleanup;
    }
    
    // 加载默认provider
    default_prov = OSSL_PROVIDER_load(libctx, "default");
    if (!default_prov) {
        handle_error("无法加载默认Provider");
        goto cleanup;
    }
    
    // 设置TEE Provider的私钥路径
    tee_provider_set_private_key_path("./certs/client.key");
    
    // 添加TEE Provider
    extern int OSSL_provider_init(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *, const OSSL_DISPATCH **, void **);
    if (OSSL_PROVIDER_add_builtin(libctx, "tee", OSSL_provider_init) == 0) {
        handle_error("无法添加TEE Provider");
        goto cleanup;
    }
    
    // 加载TEE Provider
    tee_prov = OSSL_PROVIDER_load(libctx, "tee");
    if (!tee_prov) {
        handle_error("无法加载TEE Provider");
        goto cleanup;
    }
    
    printf("[INFO] TEE Provider加载成功\n");
    
    // 加载私钥
    FILE *fp = fopen("./certs/client.key", "rb");
    if (!fp) {
        printf("[ERROR] 无法打开私钥文件\n");
        goto cleanup;
    }
    
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!pkey) {
        handle_error("无法加载私钥");
        goto cleanup;
    }
    
    printf("[INFO] 私钥加载成功\n");
    
    // 创建签名上下文
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        handle_error("无法创建签名上下文");
        goto cleanup;
    }
    
    // 尝试使用TEE Provider进行签名
    printf("[INFO] 尝试使用TEE Provider进行签名...\n");
    
    // 使用标准方式初始化签名（TEE Provider应该在背后被调用）
    printf("[INFO] 使用标准方式初始化签名（TEE Provider应该接管私钥操作）\n");
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        handle_error("签名初始化失败");
        goto cleanup;
    }
    printf("[INFO] 签名初始化成功\n");
    
    // 添加要签名的数据
    if (EVP_DigestSignUpdate(mdctx, test_data, strlen(test_data)) <= 0) {
        handle_error("签名更新失败");
        goto cleanup;
    }
    
    // 获取签名长度
    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) <= 0) {
        handle_error("获取签名长度失败");
        goto cleanup;
    }
    
    // 分配签名内存
    signature = OPENSSL_malloc(sig_len);
    if (!signature) {
        printf("[ERROR] 内存分配失败\n");
        goto cleanup;
    }
    
    // 执行签名
    printf("[INFO] 执行签名操作...\n");
    if (EVP_DigestSignFinal(mdctx, signature, &sig_len) <= 0) {
        handle_error("签名失败");
        goto cleanup;
    }
    
    printf("[SUCCESS] 签名成功！\n");
    printf("签名长度: %zu 字节\n", sig_len);
    printf("签名数据: ");
    for (size_t i = 0; i < (sig_len > 32 ? 32 : sig_len); i++) {
        printf("%02x", signature[i]);
    }
    if (sig_len > 32) {
        printf("...");
    }
    printf("\n");
    
    ret = 0;
    
cleanup:
    if (signature) OPENSSL_free(signature);
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (tee_prov) OSSL_PROVIDER_unload(tee_prov);
    if (default_prov) OSSL_PROVIDER_unload(default_prov);
    if (libctx) OSSL_LIB_CTX_free(libctx);
    
    printf("=== 测试完成 ===\n");
    return ret;
}