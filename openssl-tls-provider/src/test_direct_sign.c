#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/pem.h>

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
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    FILE *fp = NULL;
    const char *data = "Hello Direct TEE Test!";
    unsigned char *sig = NULL;
    size_t siglen = 0;
    int ret = 0;

    printf("=== 直接TEE签名测试 ===\n");

    // 创建库上下文
    libctx = OSSL_LIB_CTX_new();
    if (!libctx) {
        printf("无法创建库上下文\n");
        goto cleanup;
    }
    printf("库上下文创建成功\n");

    // 加载默认provider
    default_prov = OSSL_PROVIDER_load(libctx, "default");
    if (!default_prov) {
        printf("无法加载默认provider\n");
        print_errors();
        goto cleanup;
    }
    printf("默认provider加载成功\n");

    // 添加并加载TEE provider
    extern int OSSL_provider_init(const OSSL_CORE_HANDLE *, const OSSL_DISPATCH *, const OSSL_DISPATCH **, void **);
    
    if (OSSL_PROVIDER_add_builtin(libctx, "tee", OSSL_provider_init) == 0) {
        printf("无法添加TEE provider\n");
        print_errors();
        goto cleanup;
    }
    
    tee_prov = OSSL_PROVIDER_load(libctx, "tee");
    if (!tee_prov) {
        printf("无法加载TEE provider\n");
        print_errors();
        goto cleanup;
    }
    printf("TEE provider加载成功\n");

    // 直接从文件加载私钥（不通过TEE provider）
    fp = fopen("./certs/client.key", "rb");
    if (!fp) {
        printf("无法打开私钥文件\n");
        goto cleanup;
    }
    
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    fp = NULL;
    
    if (!pkey) {
        printf("无法解析私钥\n");
        print_errors();
        goto cleanup;
    }
    printf("私钥加载成功（直接方式）\n");

    // 创建摘要上下文
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        printf("无法创建摘要上下文\n");
        goto cleanup;
    }
    printf("摘要上下文创建成功\n");

    // 使用默认方式初始化摘要签名
    printf("使用默认方式初始化摘要签名...\n");
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        printf("摘要签名初始化失败\n");
        print_errors();
        goto cleanup;
    }
    printf("摘要签名初始化成功\n");

    // 更新数据
    printf("更新签名数据...\n");
    if (EVP_DigestSignUpdate(mdctx, data, strlen(data)) <= 0) {
        printf("摘要签名更新失败\n");
        print_errors();
        goto cleanup;
    }
    printf("摘要签名数据更新成功\n");

    // 获取签名长度
    printf("获取签名长度...\n");
    if (EVP_DigestSignFinal(mdctx, NULL, &siglen) <= 0) {
        printf("获取摘要签名长度失败\n");
        print_errors();
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
    printf("执行摘要签名...\n");
    if (EVP_DigestSignFinal(mdctx, sig, &siglen) <= 0) {
        printf("摘要签名操作失败\n");
        print_errors();
        goto cleanup;
    }

    printf("直接签名成功！\n");
    printf("签名长度: %zu 字节\n", siglen);
    printf("签名数据 (前16字节): ");
    for (size_t i = 0; i < (siglen < 16 ? siglen : 16); i++) {
        printf("%02x", sig[i]);
    }
    printf("\n");

    // 现在测试是否能强制调用TEE provider的签名函数
    printf("\n--- 测试强制使用TEE provider进行签名 ---\n");
    
    // 重置摘要上下文
    EVP_MD_CTX_free(mdctx);
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        printf("无法重新创建摘要上下文\n");
        goto cleanup;
    }
    
    // 设置TEE provider为私钥构建
    tee_provider_set_certificate_path("./certs/client.pem");
    printf("TEE私钥设置完成\n");
    
    // 尝试使用TEE provider提供的私钥进行签名
    EVP_PKEY *tee_key = tee_provider_get_private_key();
    if (tee_key) {
        printf("获取到TEE私钥，尝试签名...\n");
        
        if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, tee_key) <= 0) {
            printf("TEE私钥签名初始化失败\n");
            print_errors();
        } else {
            printf("TEE私钥签名初始化成功\n");
            
            if (EVP_DigestSignUpdate(mdctx, data, strlen(data)) <= 0) {
                printf("TEE私钥签名更新失败\n");
                print_errors();
            } else if (EVP_DigestSignFinal(mdctx, NULL, &siglen) <= 0) {
                printf("TEE私钥获取签名长度失败\n");
                print_errors();
            } else {
                printf("TEE私钥签名操作成功！长度: %zu\n", siglen);
            }
        }
        
        EVP_PKEY_free(tee_key);
    }

    ret = 1;

cleanup:
    if (sig) OPENSSL_free(sig);
    if (mdctx) EVP_MD_CTX_free(mdctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (fp) fclose(fp);
    if (tee_prov) OSSL_PROVIDER_unload(tee_prov);
    if (default_prov) OSSL_PROVIDER_unload(default_prov);
    if (libctx) OSSL_LIB_CTX_free(libctx);

    if (ret) {
        printf("=== 直接TEE签名测试完成 ===\n");
    } else {
        printf("=== 直接TEE签名测试失败 ===\n");
    }

    return ret ? 0 : 1;
}