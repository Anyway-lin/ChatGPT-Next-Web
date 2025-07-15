#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* 全局变量存储私钥 */
static EVP_PKEY *g_device_private_key = NULL;

/* 错误处理函数 */
static void tee_provider_error(const char *msg) {
    fprintf(stderr, "TEE Provider Error: %s\n", msg);
}

/* TEE模拟：签名操作 */
static int tee_sign_operation(const unsigned char *tbs, size_t tbslen,
                             unsigned char *sig, size_t *siglen) {
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;
    
    printf("TEE Provider: 执行签名操作 (数据长度: %zu)\n", tbslen);
    
    if (!g_device_private_key) {
        tee_provider_error("设备私钥未加载");
        return 0;
    }
    
    ctx = EVP_PKEY_CTX_new(g_device_private_key, NULL);
    if (!ctx) {
        tee_provider_error("创建PKEY上下文失败");
        return 0;
    }
    
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        tee_provider_error("初始化签名操作失败");
        goto end;
    }
    
    /* 设置签名填充模式为PKCS1 */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        tee_provider_error("设置RSA填充模式失败");
        goto end;
    }
    
    /* 执行签名 */
    if (EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen) <= 0) {
        tee_provider_error("签名操作失败");
        goto end;
    }
    
    printf("TEE Provider: 签名成功 (签名长度: %zu)\n", *siglen);
    ret = 1;
    
end:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* 加载设备私钥到TEE Provider */
int tee_provider_load_private_key(const char *key_file) {
    FILE *fp = NULL;
    
    printf("TEE Provider: 加载私钥文件 %s\n", key_file);
    
    fp = fopen(key_file, "r");
    if (!fp) {
        tee_provider_error("无法打开私钥文件");
        return 0;
    }
    
    g_device_private_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!g_device_private_key) {
        tee_provider_error("读取私钥失败");
        return 0;
    }
    
    printf("TEE Provider: 私钥加载成功\n");
    return 1;
}

/* 清理函数 */
void tee_provider_cleanup(void) {
    printf("TEE Provider: 清理资源\n");
    if (g_device_private_key) {
        EVP_PKEY_free(g_device_private_key);
        g_device_private_key = NULL;
    }
}

/* 测试接口：直接进行签名验证 */
int tee_provider_test_sign_verify(void) {
    const char *test_data = "Hello, TEE Provider!";
    unsigned char sig[512];
    size_t siglen = sizeof(sig);
    EVP_PKEY_CTX *verify_ctx = NULL;
    int ret = 0;
    
    if (!g_device_private_key) {
        tee_provider_error("私钥未加载");
        return 0;
    }
    
    printf("TEE Provider: 开始签名验证测试\n");
    
    /* 进行签名 */
    if (!tee_sign_operation((const unsigned char*)test_data, strlen(test_data), sig, &siglen)) {
        return 0;
    }
    
    /* 进行验证 */
    verify_ctx = EVP_PKEY_CTX_new(g_device_private_key, NULL);
    if (!verify_ctx) {
        tee_provider_error("创建验证上下文失败");
        return 0;
    }
    
    if (EVP_PKEY_verify_init(verify_ctx) <= 0) {
        tee_provider_error("初始化验证操作失败");
        goto end;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(verify_ctx, RSA_PKCS1_PADDING) <= 0) {
        tee_provider_error("设置验证填充模式失败");
        goto end;
    }
    
    if (EVP_PKEY_verify(verify_ctx, sig, siglen, (const unsigned char*)test_data, strlen(test_data)) <= 0) {
        tee_provider_error("签名验证失败");
        goto end;
    }
    
    printf("TEE Provider: ✓ 签名验证测试成功！\n");
    ret = 1;
    
end:
    EVP_PKEY_CTX_free(verify_ctx);
    return ret;
}