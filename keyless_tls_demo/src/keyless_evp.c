#include "keyless_evp.h"
#include "tee_mock.h"
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

static ENGINE *keyless_engine = NULL;

// TEE签名回调函数
static int keyless_rsa_sign(int type, const unsigned char *msg, unsigned int msg_len,
                           unsigned char *sig, unsigned int *sig_len, const RSA *rsa) {
    struct TeeBlob inData, outData;
    int ret;
    
    printf("keyless_rsa_sign called: type=%d, msg_len=%u\n", type, msg_len);
    
    // 准备TEE输入数据
    inData.data = (uint8_t *)msg;
    inData.dataLength = msg_len;
    memset(&outData, 0, sizeof(outData));
    
    // 调用TEE签名操作
    ret = TeeKeylessOperation(KM_PURPOSE_SIGN, KM_PAD_RSA_PKCS1_1_5_SIGN, &inData, &outData);
    if (ret != 0) {
        fprintf(stderr, "TEE signing operation failed: %d\n", ret);
        return 0;
    }
    
    // 检查输出缓冲区大小
    if (sig == NULL) {
        *sig_len = outData.dataLength;
        free(outData.data);
        return 1;
    }
    
    if (*sig_len < outData.dataLength) {
        fprintf(stderr, "Signature buffer too small: need %zu, have %u\n", 
                outData.dataLength, *sig_len);
        free(outData.data);
        return 0;
    }
    
    // 复制签名数据
    memcpy(sig, outData.data, outData.dataLength);
    *sig_len = outData.dataLength;
    
    free(outData.data);
    
    printf("TEE signing successful: signature length = %u\n", *sig_len);
    return 1;
}

// TEE解密回调函数
static int keyless_rsa_decrypt(int flen, const unsigned char *from, unsigned char *to,
                              RSA *rsa, int padding) {
    struct TeeBlob inData, outData;
    int ret;
    uint32_t tee_padding;
    
    printf("keyless_rsa_decrypt called: flen=%d, padding=%d\n", flen, padding);
    
    // 转换填充模式
    switch (padding) {
        case RSA_PKCS1_PADDING:
            tee_padding = KM_PAD_RSA_PKCS1_1_5_ENCRYPT;
            break;
        case RSA_PKCS1_OAEP_PADDING:
            tee_padding = KM_PAD_RSA_OAEP;
            break;
        case RSA_NO_PADDING:
            tee_padding = KM_PAD_NONE;
            break;
        default:
            fprintf(stderr, "Unsupported padding mode: %d\n", padding);
            return -1;
    }
    
    // 准备TEE输入数据
    inData.data = (uint8_t *)from;
    inData.dataLength = flen;
    memset(&outData, 0, sizeof(outData));
    
    // 调用TEE解密操作
    ret = TeeKeylessOperation(KM_PURPOSE_DECRYPT, tee_padding, &inData, &outData);
    if (ret != 0) {
        fprintf(stderr, "TEE decrypt operation failed: %d\n", ret);
        return -1;
    }
    
    // 复制解密数据
    memcpy(to, outData.data, outData.dataLength);
    int result_len = outData.dataLength;
    
    free(outData.data);
    
    printf("TEE decrypt successful: result length = %d\n", result_len);
    return result_len;
}

int keyless_evp_init(void) {
    RSA_METHOD *rsa_method;
    
    // 创建自定义ENGINE
    keyless_engine = ENGINE_new();
    if (!keyless_engine) {
        fprintf(stderr, "Failed to create keyless engine\n");
        return -1;
    }
    
    // 设置ENGINE信息
    if (!ENGINE_set_id(keyless_engine, "keyless_tee") ||
        !ENGINE_set_name(keyless_engine, "Keyless TEE Engine")) {
        fprintf(stderr, "Failed to set engine id/name\n");
        ENGINE_free(keyless_engine);
        keyless_engine = NULL;
        return -1;
    }
    
    // 创建自定义RSA方法
    rsa_method = RSA_meth_new("Keyless TEE RSA", RSA_METHOD_FLAG_NO_CHECK);
    if (!rsa_method) {
        fprintf(stderr, "Failed to create RSA method\n");
        ENGINE_free(keyless_engine);
        keyless_engine = NULL;
        return -1;
    }
    
    // 设置RSA方法回调
    RSA_meth_set_sign(rsa_method, keyless_rsa_sign);
    RSA_meth_set_priv_dec(rsa_method, keyless_rsa_decrypt);
    
    // 将RSA方法设置到ENGINE
    if (!ENGINE_set_RSA(keyless_engine, rsa_method)) {
        fprintf(stderr, "Failed to set RSA method to engine\n");
        RSA_meth_free(rsa_method);
        ENGINE_free(keyless_engine);
        keyless_engine = NULL;
        return -1;
    }
    
    // 初始化ENGINE
    if (!ENGINE_init(keyless_engine)) {
        fprintf(stderr, "Failed to initialize keyless engine\n");
        ENGINE_free(keyless_engine);
        keyless_engine = NULL;
        return -1;
    }
    
    printf("Keyless EVP engine initialized successfully\n");
    return 0;
}

void keyless_evp_cleanup(void) {
    if (keyless_engine) {
        ENGINE_finish(keyless_engine);
        ENGINE_free(keyless_engine);
        keyless_engine = NULL;
    }
}

EVP_PKEY *create_keyless_evp_pkey(const char *public_key_pem_file) {
    FILE *key_file;
    EVP_PKEY *original_key = NULL;
    EVP_PKEY *keyless_pkey = NULL;
    RSA *rsa = NULL;
    RSA *keyless_rsa = NULL;
    
    if (!keyless_engine) {
        fprintf(stderr, "Keyless engine not initialized\n");
        return NULL;
    }
    
    // 加载原始私钥文件以提取公钥部分
    key_file = fopen(public_key_pem_file, "r");
    if (!key_file) {
        fprintf(stderr, "Failed to open key file: %s\n", public_key_pem_file);
        return NULL;
    }
    
    original_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    
    if (!original_key) {
        fprintf(stderr, "Failed to load original key\n");
        return NULL;
    }
    
    // 提取RSA公钥
    rsa = EVP_PKEY_get1_RSA(original_key);
    if (!rsa) {
        fprintf(stderr, "Failed to extract RSA key\n");
        EVP_PKEY_free(original_key);
        return NULL;
    }
    
    // 创建新的RSA对象，只包含公钥部分
    keyless_rsa = RSA_new();
    if (!keyless_rsa) {
        fprintf(stderr, "Failed to create keyless RSA\n");
        RSA_free(rsa);
        EVP_PKEY_free(original_key);
        return NULL;
    }
    
    // 复制公钥参数
    const BIGNUM *n, *e;
    RSA_get0_key(rsa, &n, &e, NULL); // 获取公钥参数，不获取私钥d
    
    BIGNUM *n_copy = BN_dup(n);
    BIGNUM *e_copy = BN_dup(e);
    
    if (!n_copy || !e_copy) {
        fprintf(stderr, "Failed to copy public key parameters\n");
        BN_free(n_copy);
        BN_free(e_copy);
        RSA_free(keyless_rsa);
        RSA_free(rsa);
        EVP_PKEY_free(original_key);
        return NULL;
    }
    
    // 设置公钥参数到新的RSA对象
    if (!RSA_set0_key(keyless_rsa, n_copy, e_copy, NULL)) {
        fprintf(stderr, "Failed to set public key parameters\n");
        BN_free(n_copy);
        BN_free(e_copy);
        RSA_free(keyless_rsa);
        RSA_free(rsa);
        EVP_PKEY_free(original_key);
        return NULL;
    }
    
    // 设置ENGINE到RSA对象
    if (!RSA_set_method(keyless_rsa, ENGINE_get_RSA(keyless_engine))) {
        fprintf(stderr, "Failed to set keyless method to RSA\n");
        RSA_free(keyless_rsa);
        RSA_free(rsa);
        EVP_PKEY_free(original_key);
        return NULL;
    }
    
    // 创建EVP_PKEY对象
    keyless_pkey = EVP_PKEY_new();
    if (!keyless_pkey) {
        fprintf(stderr, "Failed to create keyless EVP_PKEY\n");
        RSA_free(keyless_rsa);
        RSA_free(rsa);
        EVP_PKEY_free(original_key);
        return NULL;
    }
    
    // 设置RSA到EVP_PKEY
    if (!EVP_PKEY_set1_RSA(keyless_pkey, keyless_rsa)) {
        fprintf(stderr, "Failed to set RSA to EVP_PKEY\n");
        EVP_PKEY_free(keyless_pkey);
        RSA_free(keyless_rsa);
        RSA_free(rsa);
        EVP_PKEY_free(original_key);
        return NULL;
    }
    
    // 清理临时对象
    RSA_free(keyless_rsa);
    RSA_free(rsa);
    EVP_PKEY_free(original_key);
    
    printf("Keyless EVP_PKEY created successfully\n");
    return keyless_pkey;
}