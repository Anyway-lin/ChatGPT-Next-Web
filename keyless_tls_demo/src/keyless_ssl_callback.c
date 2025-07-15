#include "keyless_ssl_callback.h"
#include "tee_mock.h"
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

// 全局变量存储证书和公钥信息
static X509 *g_device_cert = NULL;
static EVP_PKEY *g_public_key = NULL;

// 自定义签名上下文
typedef struct {
    EVP_PKEY *public_key;
} KEYLESS_SIGN_CTX;

// 自定义签名方法回调
static int keyless_sign_init(EVP_PKEY_CTX *ctx) {
    printf("keyless_sign_init called\n");
    
    KEYLESS_SIGN_CTX *sign_ctx = malloc(sizeof(KEYLESS_SIGN_CTX));
    if (!sign_ctx) {
        return 0;
    }
    
    sign_ctx->public_key = EVP_PKEY_CTX_get0_pkey(ctx);
    EVP_PKEY_CTX_set_data(ctx, sign_ctx);
    
    return 1;
}

static void keyless_sign_cleanup(EVP_PKEY_CTX *ctx) {
    KEYLESS_SIGN_CTX *sign_ctx = EVP_PKEY_CTX_get_data(ctx);
    if (sign_ctx) {
        free(sign_ctx);
        EVP_PKEY_CTX_set_data(ctx, NULL);
    }
}

static int keyless_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                       const unsigned char *tbs, size_t tbslen) {
    struct TeeBlob inData, outData;
    int ret;
    
    printf("keyless_sign called: tbslen=%zu\n", tbslen);
    
    // 准备TEE输入数据
    inData.data = (uint8_t *)tbs;
    inData.dataLength = tbslen;
    memset(&outData, 0, sizeof(outData));
    
    // 调用TEE签名操作
    ret = TeeKeylessOperation(KM_PURPOSE_SIGN, KM_PAD_RSA_PKCS1_1_5_SIGN, &inData, &outData);
    if (ret != 0) {
        fprintf(stderr, "TEE signing operation failed: %d\n", ret);
        return 0;
    }
    
    // 检查输出缓冲区大小
    if (sig == NULL) {
        *siglen = outData.dataLength;
        free(outData.data);
        return 1;
    }
    
    if (*siglen < outData.dataLength) {
        fprintf(stderr, "Signature buffer too small: need %zu, have %zu\n", 
                outData.dataLength, *siglen);
        free(outData.data);
        return 0;
    }
    
    // 复制签名数据
    memcpy(sig, outData.data, outData.dataLength);
    *siglen = outData.dataLength;
    
    free(outData.data);
    
    printf("TEE signing successful: signature length = %zu\n", *siglen);
    return 1;
}

// 客户端证书回调函数
static int client_cert_cb(SSL *ssl, X509 **x509, EVP_PKEY **pkey) {
    printf("client_cert_cb called - providing keyless certificate and key\n");
    
    if (!g_device_cert || !g_public_key) {
        fprintf(stderr, "Keyless certificate or key not initialized\n");
        return 0;
    }
    
    // 返回证书（增加引用计数）
    *x509 = g_device_cert;
    X509_up_ref(g_device_cert);
    
    // 返回公钥（增加引用计数）
    *pkey = g_public_key;
    EVP_PKEY_up_ref(g_public_key);
    
    printf("Provided certificate and keyless private key to SSL context\n");
    return 1;
}

// 私钥签名钩子 - 这个函数将在需要私钥签名时被调用
static int keyless_pkey_sign_init_hook(EVP_PKEY_CTX *ctx) {
    // 对于演示，我们直接处理签名
    return keyless_sign_init(ctx);
}

int keyless_ssl_callback_init(const char *device_key_path, const char *device_cert_path) {
    FILE *cert_file, *key_file;
    EVP_PKEY *full_key = NULL;
    
    // 清理之前的状态
    keyless_ssl_callback_cleanup();
    
    // 加载设备证书
    cert_file = fopen(device_cert_path, "r");
    if (!cert_file) {
        fprintf(stderr, "Failed to open device certificate file: %s\n", device_cert_path);
        return -1;
    }
    
    g_device_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    
    if (!g_device_cert) {
        fprintf(stderr, "Failed to load device certificate\n");
        return -1;
    }
    
    // 加载设备私钥文件以提取公钥
    key_file = fopen(device_key_path, "r");
    if (!key_file) {
        fprintf(stderr, "Failed to open device key file: %s\n", device_key_path);
        X509_free(g_device_cert);
        g_device_cert = NULL;
        return -1;
    }
    
    full_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    
    if (!full_key) {
        fprintf(stderr, "Failed to load device private key\n");
        X509_free(g_device_cert);
        g_device_cert = NULL;
        return -1;
    }
    
    // 直接从原始密钥提取公钥部分
    unsigned char *pub_der = NULL;
    int pub_der_len = i2d_PUBKEY(full_key, &pub_der);
    if (pub_der_len <= 0) {
        fprintf(stderr, "Failed to extract public key\n");
        EVP_PKEY_free(full_key);
        X509_free(g_device_cert);
        g_device_cert = NULL;
        return -1;
    }
    
    // 从DER重新创建只包含公钥的EVP_PKEY
    const unsigned char *pub_der_ptr = pub_der;
    g_public_key = d2i_PUBKEY(NULL, &pub_der_ptr, pub_der_len);
    OPENSSL_free(pub_der);
    EVP_PKEY_free(full_key);
    
    if (!g_public_key) {
        fprintf(stderr, "Failed to create public-only key\n");
        X509_free(g_device_cert);
        g_device_cert = NULL;
        return -1;
    }
    
    printf("Keyless SSL callback system initialized successfully\n");
    return 0;
}

int keyless_ssl_set_callback(SSL_CTX *ctx) {
    if (!g_device_cert || !g_public_key) {
        fprintf(stderr, "Keyless SSL callback system not initialized\n");
        return -1;
    }
    
    // 设置客户端证书回调
    SSL_CTX_set_client_cert_cb(ctx, client_cert_cb);
    
    printf("Keyless SSL callback set successfully\n");
    return 0;
}

void keyless_ssl_callback_cleanup(void) {
    if (g_device_cert) {
        X509_free(g_device_cert);
        g_device_cert = NULL;
    }
    
    if (g_public_key) {
        EVP_PKEY_free(g_public_key);
        g_public_key = NULL;
    }
}