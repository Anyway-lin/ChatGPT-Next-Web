#include "tee_sign.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

// 全局变量
static int tee_initialized = 0;

// 内部密钥存储结构
typedef struct {
    EVP_PKEY *private_key;  // 私钥（模拟在TEE中）
    EVP_PKEY *public_key;   // 公钥
} tee_key_pair_t;

// 存储已创建的密钥对（模拟TEE密钥存储）
static tee_key_pair_t *key_pairs[256] = {0};

/**
 * 初始化TEE环境
 */
tee_result_t tee_init(void) {
    if (tee_initialized) {
        return TEE_SUCCESS;
    }
    
    // 初始化OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // 初始化随机数生成器
    if (RAND_poll() != 1) {
        fprintf(stderr, "TEE: Failed to seed random number generator\n");
        return TEE_ERROR_GENERIC;
    }
    
    tee_initialized = 1;
    printf("TEE: Environment initialized successfully\n");
    return TEE_SUCCESS;
}

/**
 * 清理TEE环境
 */
void tee_cleanup(void) {
    if (!tee_initialized) {
        return;
    }
    
    // 清理所有密钥对
    for (int i = 0; i < 256; i++) {
        if (key_pairs[i]) {
            if (key_pairs[i]->private_key) {
                EVP_PKEY_free(key_pairs[i]->private_key);
            }
            if (key_pairs[i]->public_key) {
                EVP_PKEY_free(key_pairs[i]->public_key);
            }
            free(key_pairs[i]);
            key_pairs[i] = NULL;
        }
    }
    
    EVP_cleanup();
    ERR_free_strings();
    tee_initialized = 0;
    printf("TEE: Environment cleaned up\n");
}

/**
 * 生成RSA密钥对
 */
static tee_result_t generate_rsa_keypair(uint32_t key_size, tee_key_pair_t *keypair) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        fprintf(stderr, "TEE: Failed to create RSA context\n");
        return TEE_ERROR_GENERIC;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "TEE: Failed to init RSA keygen\n");
        EVP_PKEY_CTX_free(ctx);
        return TEE_ERROR_GENERIC;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size) <= 0) {
        fprintf(stderr, "TEE: Failed to set RSA key size\n");
        EVP_PKEY_CTX_free(ctx);
        return TEE_ERROR_GENERIC;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "TEE: Failed to generate RSA key\n");
        EVP_PKEY_CTX_free(ctx);
        return TEE_ERROR_GENERIC;
    }
    
    keypair->private_key = pkey;
    keypair->public_key = pkey;
    EVP_PKEY_up_ref(pkey);  // 增加引用计数
    
    EVP_PKEY_CTX_free(ctx);
    printf("TEE: Generated RSA-%d key pair\n", key_size);
    return TEE_SUCCESS;
}

/**
 * 生成ECDSA密钥对
 */
static tee_result_t generate_ecdsa_keypair(tee_algorithm_t alg, tee_key_pair_t *keypair) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int curve_nid;
    
    // 根据算法选择曲线
    switch (alg) {
        case TEE_ALG_ECDSA_SHA256:
            curve_nid = NID_X9_62_prime256v1;  // P-256
            break;
        case TEE_ALG_ECDSA_SHA384:
            curve_nid = NID_secp384r1;         // P-384
            break;
        case TEE_ALG_ECDSA_SHA512:
            curve_nid = NID_secp521r1;         // P-521
            break;
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
    
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) {
        fprintf(stderr, "TEE: Failed to create EC context\n");
        return TEE_ERROR_GENERIC;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "TEE: Failed to init EC keygen\n");
        EVP_PKEY_CTX_free(ctx);
        return TEE_ERROR_GENERIC;
    }
    
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve_nid) <= 0) {
        fprintf(stderr, "TEE: Failed to set EC curve\n");
        EVP_PKEY_CTX_free(ctx);
        return TEE_ERROR_GENERIC;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "TEE: Failed to generate EC key\n");
        EVP_PKEY_CTX_free(ctx);
        return TEE_ERROR_GENERIC;
    }
    
    keypair->private_key = pkey;
    keypair->public_key = pkey;
    EVP_PKEY_up_ref(pkey);  // 增加引用计数
    
    EVP_PKEY_CTX_free(ctx);
    printf("TEE: Generated ECDSA key pair for curve %s\n", 
           OBJ_nid2sn(curve_nid));
    return TEE_SUCCESS;
}

/**
 * 创建密钥句柄
 */
tee_result_t tee_create_key_handle(uint32_t key_id, tee_algorithm_t alg, 
                                  uint32_t key_size, tee_key_handle_t **handle) {
    if (!tee_initialized) {
        return TEE_ERROR_GENERIC;
    }
    
    if (!handle || key_id >= 256) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    // 检查密钥ID是否已存在
    if (key_pairs[key_id]) {
        fprintf(stderr, "TEE: Key ID %d already exists\n", key_id);
        return TEE_ERROR_GENERIC;
    }
    
    // 分配内存
    *handle = (tee_key_handle_t*)malloc(sizeof(tee_key_handle_t));
    if (!*handle) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    
    key_pairs[key_id] = (tee_key_pair_t*)malloc(sizeof(tee_key_pair_t));
    if (!key_pairs[key_id]) {
        free(*handle);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    
    memset(key_pairs[key_id], 0, sizeof(tee_key_pair_t));
    
    // 根据算法生成密钥对
    tee_result_t result;
    if (alg == TEE_ALG_RSA_PSS_SHA256 || alg == TEE_ALG_RSA_PKCS1_SHA256) {
        result = generate_rsa_keypair(key_size, key_pairs[key_id]);
    } else {
        result = generate_ecdsa_keypair(alg, key_pairs[key_id]);
    }
    
    if (result != TEE_SUCCESS) {
        free(key_pairs[key_id]);
        key_pairs[key_id] = NULL;
        free(*handle);
        return result;
    }
    
    // 填充句柄信息
    (*handle)->key_id = key_id;
    (*handle)->alg = alg;
    (*handle)->key_size = key_size;
    (*handle)->public_key = NULL;
    (*handle)->public_key_len = 0;
    
    printf("TEE: Created key handle for key ID %d\n", key_id);
    return TEE_SUCCESS;
}

/**
 * 销毁密钥句柄
 */
void tee_destroy_key_handle(tee_key_handle_t *handle) {
    if (!handle) {
        return;
    }
    
    uint32_t key_id = handle->key_id;
    
    if (key_id < 256 && key_pairs[key_id]) {
        if (key_pairs[key_id]->private_key) {
            EVP_PKEY_free(key_pairs[key_id]->private_key);
        }
        if (key_pairs[key_id]->public_key && 
            key_pairs[key_id]->public_key != key_pairs[key_id]->private_key) {
            EVP_PKEY_free(key_pairs[key_id]->public_key);
        }
        free(key_pairs[key_id]);
        key_pairs[key_id] = NULL;
    }
    
    if (handle->public_key) {
        free(handle->public_key);
    }
    
    free(handle);
    printf("TEE: Destroyed key handle for key ID %d\n", key_id);
}

/**
 * 使用TEE进行签名
 */
tee_result_t tee_sign(tee_key_handle_t *handle, const uint8_t *data, 
                     size_t data_len, uint8_t *signature, size_t *signature_len) {
    if (!handle || !data || !signature_len || handle->key_id >= 256) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    tee_key_pair_t *keypair = key_pairs[handle->key_id];
    if (!keypair || !keypair->private_key) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;
    
    // 选择哈希算法
    switch (handle->alg) {
        case TEE_ALG_RSA_PSS_SHA256:
        case TEE_ALG_RSA_PKCS1_SHA256:
        case TEE_ALG_ECDSA_SHA256:
            md = EVP_sha256();
            break;
        case TEE_ALG_ECDSA_SHA384:
            md = EVP_sha384();
            break;
        case TEE_ALG_ECDSA_SHA512:
            md = EVP_sha512();
            break;
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
    
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    
    // 初始化签名操作
    if (EVP_DigestSignInit(mdctx, &pctx, md, NULL, keypair->private_key) != 1) {
        fprintf(stderr, "TEE: Failed to init digest sign\n");
        EVP_MD_CTX_free(mdctx);
        return TEE_ERROR_GENERIC;
    }
    
    // 设置RSA填充模式
    if (handle->alg == TEE_ALG_RSA_PSS_SHA256) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1) {
            fprintf(stderr, "TEE: Failed to set PSS padding\n");
            EVP_MD_CTX_free(mdctx);
            return TEE_ERROR_GENERIC;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1) {
            fprintf(stderr, "TEE: Failed to set PSS salt length\n");
            EVP_MD_CTX_free(mdctx);
            return TEE_ERROR_GENERIC;
        }
    } else if (handle->alg == TEE_ALG_RSA_PKCS1_SHA256) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) != 1) {
            fprintf(stderr, "TEE: Failed to set PKCS1 padding\n");
            EVP_MD_CTX_free(mdctx);
            return TEE_ERROR_GENERIC;
        }
    }
    
    // 提供要签名的数据
    if (EVP_DigestSignUpdate(mdctx, data, data_len) != 1) {
        fprintf(stderr, "TEE: Failed to update digest\n");
        EVP_MD_CTX_free(mdctx);
        return TEE_ERROR_GENERIC;
    }
    
    // 获取签名长度
    size_t sig_len = *signature_len;
    if (EVP_DigestSignFinal(mdctx, signature, &sig_len) != 1) {
        fprintf(stderr, "TEE: Failed to finalize signature\n");
        EVP_MD_CTX_free(mdctx);
        return TEE_ERROR_GENERIC;
    }
    
    *signature_len = sig_len;
    EVP_MD_CTX_free(mdctx);
    
    printf("TEE: Successfully signed %zu bytes of data, signature length: %zu\n", 
           data_len, sig_len);
    return TEE_SUCCESS;
}

/**
 * 获取公钥
 */
tee_result_t tee_get_public_key(tee_key_handle_t *handle, uint8_t *public_key, 
                               size_t *public_key_len) {
    if (!handle || !public_key_len || handle->key_id >= 256) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    tee_key_pair_t *keypair = key_pairs[handle->key_id];
    if (!keypair || !keypair->public_key) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    
    // 将公钥编码为DER格式
    unsigned char *der = NULL;
    int der_len = i2d_PUBKEY(keypair->public_key, &der);
    if (der_len <= 0) {
        fprintf(stderr, "TEE: Failed to encode public key\n");
        return TEE_ERROR_GENERIC;
    }
    
    if (*public_key_len < (size_t)der_len) {
        *public_key_len = der_len;
        OPENSSL_free(der);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    memcpy(public_key, der, der_len);
    *public_key_len = der_len;
    OPENSSL_free(der);
    
    printf("TEE: Retrieved public key for key ID %d, length: %zu\n", 
           handle->key_id, *public_key_len);
    return TEE_SUCCESS;
}

/**
 * 获取签名算法名称
 */
const char* tee_get_algorithm_name(tee_algorithm_t alg) {
    switch (alg) {
        case TEE_ALG_RSA_PSS_SHA256:
            return "RSA-PSS-SHA256";
        case TEE_ALG_RSA_PKCS1_SHA256:
            return "RSA-PKCS1-SHA256";
        case TEE_ALG_ECDSA_SHA256:
            return "ECDSA-SHA256";
        case TEE_ALG_ECDSA_SHA384:
            return "ECDSA-SHA384";
        case TEE_ALG_ECDSA_SHA512:
            return "ECDSA-SHA512";
        default:
            return "Unknown";
    }
}