#include "keyless_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

// 全局变量
static ENGINE *keyless_engine = NULL;
static int engine_initialized = 0;
static long keyless_engine_sign_count = 0;

// 前向声明
static int keyless_rsa_priv_enc(int flen, const unsigned char *from,
                               unsigned char *to, RSA *rsa, int padding);
static int keyless_rsa_priv_dec(int flen, const unsigned char *from,
                               unsigned char *to, RSA *rsa, int padding);
static int keyless_rsa_sign(int type, const unsigned char *m, unsigned int m_length,
                           unsigned char *sigret, unsigned int *siglen, const RSA *rsa);
static int keyless_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                             unsigned char *sig, unsigned int *siglen,
                             const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

// RSA方法表
static RSA_METHOD *keyless_rsa_method = NULL;

// ECDSA方法表  
static EC_KEY_METHOD *keyless_ec_method = NULL;

// 全局TEE句柄映射（临时解决方案）
static keyless_engine_key_t *global_rsa_keyless_data = NULL;
static keyless_engine_key_t *global_ec_keyless_data = NULL;

/**
 * 获取keyless私钥数据
 */
static keyless_engine_key_t* get_keyless_data_from_rsa(const RSA *rsa) {
    keyless_engine_key_t *data = (keyless_engine_key_t*)RSA_get_ex_data(rsa, 0);
    if (!data && global_rsa_keyless_data) {
        printf("Keyless Engine: Using global RSA keyless data fallback\n");
        return global_rsa_keyless_data;
    }
    return data;
}

static keyless_engine_key_t* get_keyless_data_from_ec(const EC_KEY *ec) {
    keyless_engine_key_t *data = (keyless_engine_key_t*)EC_KEY_get_ex_data(ec, 0);
    if (!data && global_ec_keyless_data) {
        printf("Keyless Engine: Using global EC keyless data fallback\n");
        return global_ec_keyless_data;
    }
    return data;
}

/**
 * RSA私钥加密（用于签名）
 */
static int keyless_rsa_priv_enc(int flen, const unsigned char *from,
                               unsigned char *to, RSA *rsa, int padding) {
    keyless_engine_key_t *keyless_data = get_keyless_data_from_rsa(rsa);
    if (!keyless_data || !keyless_data->tee_handle) {
        printf("Keyless Engine: No TEE handle for RSA private encrypt\n");
        return -1;
    }
    
    printf("Keyless Engine: RSA private encrypt called (TEE signing)\n");
    printf("  Data length: %d, Padding: %d\n", flen, padding);
    
    // 使用TEE进行签名
    size_t sig_len = RSA_size(rsa);
    tee_result_t result = tee_sign(keyless_data->tee_handle, from, flen, to, &sig_len);
    
    if (result != TEE_SUCCESS) {
        printf("Keyless Engine: TEE signing failed: %d\n", result);
        return -1;
    }
    
    keyless_engine_sign_count++;
    printf("Keyless Engine: RSA signature completed via TEE, length: %zu\n", sig_len);
    return (int)sig_len;
}

/**
 * RSA私钥解密
 */
static int keyless_rsa_priv_dec(int flen, const unsigned char *from,
                               unsigned char *to, RSA *rsa, int padding) {
    printf("Keyless Engine: RSA private decrypt called (not supported in keyless mode)\n");
    // 在keyless模式下，我们通常不支持解密操作
    return -1;
}

/**
 * RSA签名
 */
static int keyless_rsa_sign(int type, const unsigned char *m, unsigned int m_length,
                           unsigned char *sigret, unsigned int *siglen, const RSA *rsa) {
    keyless_engine_key_t *keyless_data = get_keyless_data_from_rsa(rsa);
    if (!keyless_data || !keyless_data->tee_handle) {
        printf("Keyless Engine: No TEE handle for RSA sign\n");
        return 0;
    }
    
    printf("Keyless Engine: RSA sign called (type: %d, length: %u)\n", type, m_length);
    
    // 使用TEE进行签名
    size_t sig_len = *siglen;
    tee_result_t result = tee_sign(keyless_data->tee_handle, m, m_length, sigret, &sig_len);
    
    if (result != TEE_SUCCESS) {
        printf("Keyless Engine: TEE RSA signing failed: %d\n", result);
        return 0;
    }
    
    *siglen = (unsigned int)sig_len;
    keyless_engine_sign_count++;
    printf("Keyless Engine: RSA sign completed via TEE, length: %u\n", *siglen);
    return 1;
}

/**
 * ECDSA签名
 */
static int keyless_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                             unsigned char *sig, unsigned int *siglen,
                             const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey) {
    (void)type; (void)kinv; (void)r; // 避免未使用参数警告
    
    keyless_engine_key_t *keyless_data = get_keyless_data_from_ec(eckey);
    if (!keyless_data || !keyless_data->tee_handle) {
        printf("Keyless Engine: No TEE handle for ECDSA sign\n");
        return 0;
    }
    
    printf("Keyless Engine: ECDSA sign called (digest length: %d)\n", dlen);
    
    // 使用TEE进行签名
    size_t sig_len = *siglen;
    tee_result_t result = tee_sign(keyless_data->tee_handle, dgst, dlen, sig, &sig_len);
    
    if (result != TEE_SUCCESS) {
        printf("Keyless Engine: TEE ECDSA signing failed: %d\n", result);
        return 0;
    }
    
    *siglen = (unsigned int)sig_len;
    keyless_engine_sign_count++;
    printf("Keyless Engine: ECDSA sign completed via TEE, length: %u\n", *siglen);
    return 1;
}

/**
 * Engine初始化函数
 */
static int keyless_engine_initialize(ENGINE *e) {
    printf("Keyless Engine: Initializing engine\n");
    
    // 初始化TEE
    if (tee_init() != TEE_SUCCESS) {
        printf("Keyless Engine: Failed to initialize TEE\n");
        return 0;
    }
    
    // 创建自定义RSA方法
    keyless_rsa_method = RSA_meth_new("Keyless RSA method", 0);
    if (!keyless_rsa_method) {
        printf("Keyless Engine: Failed to create RSA method\n");
        return 0;
    }
    
    // 设置RSA方法
    RSA_meth_set_priv_enc(keyless_rsa_method, keyless_rsa_priv_enc);
    RSA_meth_set_priv_dec(keyless_rsa_method, keyless_rsa_priv_dec);
    RSA_meth_set_sign(keyless_rsa_method, keyless_rsa_sign);
    
    // 设置RSA方法到engine
    if (!ENGINE_set_RSA(e, keyless_rsa_method)) {
        printf("Keyless Engine: Failed to set RSA method\n");
        RSA_meth_free(keyless_rsa_method);
        return 0;
    }
    
    // 创建自定义EC方法
    keyless_ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    if (!keyless_ec_method) {
        printf("Keyless Engine: Failed to create EC method\n");
        return 0;
    }
    
    // 设置ECDSA签名方法
    EC_KEY_METHOD_set_sign(keyless_ec_method, keyless_ecdsa_sign, NULL, NULL);
    
    // 设置EC方法到engine
    if (!ENGINE_set_EC(e, keyless_ec_method)) {
        printf("Keyless Engine: Failed to set EC method\n");
        EC_KEY_METHOD_free(keyless_ec_method);
        return 0;
    }
    
    printf("Keyless Engine: Engine initialized successfully\n");
    return 1;
}

/**
 * Engine清理函数
 */
static int keyless_engine_finish(ENGINE *e) {
    (void)e; // 避免未使用参数警告
    
    printf("Keyless Engine: Finishing engine\n");
    
    if (keyless_rsa_method) {
        RSA_meth_free(keyless_rsa_method);
        keyless_rsa_method = NULL;
    }
    
    if (keyless_ec_method) {
        EC_KEY_METHOD_free(keyless_ec_method);
        keyless_ec_method = NULL;
    }
    
    tee_cleanup();
    printf("Keyless Engine: Engine finished\n");
    return 1;
}

/**
 * Engine销毁函数
 */
static int keyless_engine_destroy(ENGINE *e) {
    (void)e; // 避免未使用参数警告
    printf("Keyless Engine: Destroying engine\n");
    return 1;
}

/**
 * 初始化keyless ENGINE
 */
int keyless_engine_init(void) {
    if (engine_initialized) {
        return 1;
    }
    
    printf("Keyless Engine: Creating keyless ENGINE\n");
    
    // 创建ENGINE
    keyless_engine = ENGINE_new();
    if (!keyless_engine) {
        printf("Keyless Engine: Failed to create ENGINE\n");
        return 0;
    }
    
    // 设置ENGINE属性
    if (!ENGINE_set_id(keyless_engine, KEYLESS_ENGINE_ID) ||
        !ENGINE_set_name(keyless_engine, KEYLESS_ENGINE_NAME) ||
        !ENGINE_set_init_function(keyless_engine, keyless_engine_initialize) ||
        !ENGINE_set_finish_function(keyless_engine, keyless_engine_finish) ||
        !ENGINE_set_destroy_function(keyless_engine, keyless_engine_destroy)) {
        printf("Keyless Engine: Failed to set ENGINE properties\n");
        ENGINE_free(keyless_engine);
        keyless_engine = NULL;
        return 0;
    }
    
    // 添加ENGINE到OpenSSL
    if (!ENGINE_add(keyless_engine)) {
        printf("Keyless Engine: Failed to add ENGINE to OpenSSL\n");
        ENGINE_free(keyless_engine);
        keyless_engine = NULL;
        return 0;
    }
    
    // 初始化ENGINE
    if (!ENGINE_init(keyless_engine)) {
        printf("Keyless Engine: Failed to initialize ENGINE\n");
        ENGINE_remove(keyless_engine);
        ENGINE_free(keyless_engine);
        keyless_engine = NULL;
        return 0;
    }
    
    // 设置为默认ENGINE
    if (!ENGINE_set_default_RSA(keyless_engine) ||
        !ENGINE_set_default_EC(keyless_engine)) {
        printf("Keyless Engine: Warning - failed to set as default ENGINE\n");
        // 这不是致命错误，继续
    }
    
    engine_initialized = 1;
    printf("Keyless Engine: ENGINE setup completed successfully\n");
    printf("Keyless Engine: Sign operations performed: %ld\n", keyless_engine_sign_count);
    return 1;
}

/**
 * 清理keyless ENGINE
 */
void keyless_engine_cleanup(void) {
    if (!engine_initialized) {
        return;
    }
    
    printf("Keyless Engine: Cleaning up ENGINE\n");
    printf("Keyless Engine: Total sign operations: %ld\n", keyless_engine_sign_count);
    
    if (keyless_engine) {
        ENGINE_finish(keyless_engine);
        ENGINE_remove(keyless_engine);
        ENGINE_free(keyless_engine);
        keyless_engine = NULL;
    }
    
    engine_initialized = 0;
    printf("Keyless Engine: Cleanup completed\n");
}

/**
 * 获取keyless ENGINE实例
 */
ENGINE* keyless_engine_get(void) {
    return keyless_engine;
}

/**
 * 创建keyless RSA密钥
 */
RSA* keyless_engine_create_rsa_key(uint32_t key_id, int key_size) {
    if (!engine_initialized) {
        printf("Keyless Engine: Engine not initialized\n");
        return NULL;
    }
    
    // 创建TEE密钥句柄
    tee_key_handle_t *tee_handle = NULL;
    tee_result_t result = tee_create_key_handle(key_id, TEE_ALG_RSA_PKCS1_SHA256, 
                                                key_size, &tee_handle);
    if (result != TEE_SUCCESS) {
        printf("Keyless Engine: Failed to create TEE key handle\n");
        return NULL;
    }
    
    // 获取公钥
    unsigned char pub_key_data[4096];
    size_t pub_key_len = sizeof(pub_key_data);
    result = tee_get_public_key(tee_handle, pub_key_data, &pub_key_len);
    if (result != TEE_SUCCESS) {
        printf("Keyless Engine: Failed to get public key\n");
        tee_destroy_key_handle(tee_handle);
        return NULL;
    }
    
    // 解析公钥
    const unsigned char *p = pub_key_data;
    EVP_PKEY *temp_pkey = d2i_PUBKEY(NULL, &p, pub_key_len);
    if (!temp_pkey) {
        printf("Keyless Engine: Failed to parse public key\n");
        tee_destroy_key_handle(tee_handle);
        return NULL;
    }
    
    RSA *pub_rsa = EVP_PKEY_get1_RSA(temp_pkey);
    EVP_PKEY_free(temp_pkey);
    
    if (!pub_rsa) {
        printf("Keyless Engine: Failed to extract RSA public key\n");
        tee_destroy_key_handle(tee_handle);
        return NULL;
    }
    
    // 创建keyless数据结构
    keyless_engine_key_t *keyless_data = malloc(sizeof(keyless_engine_key_t));
    if (!keyless_data) {
        RSA_free(pub_rsa);
        tee_destroy_key_handle(tee_handle);
        return NULL;
    }
    
    keyless_data->tee_handle = tee_handle;
    keyless_data->algorithm = TEE_ALG_RSA_PKCS1_SHA256;
    keyless_data->key_size = key_size;
    keyless_data->public_key_data = malloc(pub_key_len);
    if (keyless_data->public_key_data) {
        memcpy(keyless_data->public_key_data, pub_key_data, pub_key_len);
        keyless_data->public_key_len = pub_key_len;
    } else {
        keyless_data->public_key_len = 0;
    }
    
    // 关联keyless数据到RSA密钥
    RSA_set_ex_data(pub_rsa, 0, keyless_data);
    
    // 设置全局fallback（用于处理OpenSSL内部复制的密钥对象）
    global_rsa_keyless_data = keyless_data;
    
    // 设置ENGINE方法
    RSA_set_method(pub_rsa, keyless_rsa_method);
    
    printf("Keyless Engine: Created RSA key with TEE backend (key_id: %u, size: %d)\n", 
           key_id, key_size);
    
    return pub_rsa;
}

/**
 * 创建keyless EC密钥
 */
EC_KEY* keyless_engine_create_ec_key(uint32_t key_id, int curve_nid) {
    if (!engine_initialized) {
        printf("Keyless Engine: Engine not initialized\n");
        return NULL;
    }
    
    // 根据曲线确定算法
    tee_algorithm_t alg;
    switch (curve_nid) {
        case NID_X9_62_prime256v1:
            alg = TEE_ALG_ECDSA_SHA256;
            break;
        case NID_secp384r1:
            alg = TEE_ALG_ECDSA_SHA384;
            break;
        default:
            printf("Keyless Engine: Unsupported curve NID: %d\n", curve_nid);
            return NULL;
    }
    
    // 创建TEE密钥句柄
    tee_key_handle_t *tee_handle = NULL;
    tee_result_t result = tee_create_key_handle(key_id, alg, 256, &tee_handle);
    if (result != TEE_SUCCESS) {
        printf("Keyless Engine: Failed to create TEE EC key handle\n");
        return NULL;
    }
    
    // 获取公钥
    unsigned char pub_key_data[4096];
    size_t pub_key_len = sizeof(pub_key_data);
    result = tee_get_public_key(tee_handle, pub_key_data, &pub_key_len);
    if (result != TEE_SUCCESS) {
        printf("Keyless Engine: Failed to get EC public key\n");
        tee_destroy_key_handle(tee_handle);
        return NULL;
    }
    
    // 解析公钥
    const unsigned char *p = pub_key_data;
    EVP_PKEY *temp_pkey = d2i_PUBKEY(NULL, &p, pub_key_len);
    if (!temp_pkey) {
        printf("Keyless Engine: Failed to parse EC public key\n");
        tee_destroy_key_handle(tee_handle);
        return NULL;
    }
    
    EC_KEY *pub_ec = EVP_PKEY_get1_EC_KEY(temp_pkey);
    EVP_PKEY_free(temp_pkey);
    
    if (!pub_ec) {
        printf("Keyless Engine: Failed to extract EC public key\n");
        tee_destroy_key_handle(tee_handle);
        return NULL;
    }
    
    // 创建keyless数据结构
    keyless_engine_key_t *keyless_data = malloc(sizeof(keyless_engine_key_t));
    if (!keyless_data) {
        EC_KEY_free(pub_ec);
        tee_destroy_key_handle(tee_handle);
        return NULL;
    }
    
    keyless_data->tee_handle = tee_handle;
    keyless_data->algorithm = alg;
    keyless_data->key_size = 256; // EC key size in bits
    keyless_data->public_key_data = malloc(pub_key_len);
    if (keyless_data->public_key_data) {
        memcpy(keyless_data->public_key_data, pub_key_data, pub_key_len);
        keyless_data->public_key_len = pub_key_len;
    } else {
        keyless_data->public_key_len = 0;
    }
    
    // 关联keyless数据到EC密钥
    EC_KEY_set_ex_data(pub_ec, 0, keyless_data);
    
    // 设置全局fallback（用于处理OpenSSL内部复制的密钥对象）
    global_ec_keyless_data = keyless_data;
    
    // 设置ENGINE方法
    EC_KEY_set_method(pub_ec, keyless_ec_method);
    
    printf("Keyless Engine: Created EC key with TEE backend (key_id: %u, curve: %d)\n", 
           key_id, curve_nid);
    
    return pub_ec;
}

/**
 * 创建keyless EVP_PKEY
 */
EVP_PKEY* keyless_engine_create_evp_pkey(uint32_t key_id, tee_algorithm_t alg, int key_size) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        return NULL;
    }
    
    if (alg == TEE_ALG_RSA_PKCS1_SHA256 || alg == TEE_ALG_RSA_PSS_SHA256) {
        RSA *rsa = keyless_engine_create_rsa_key(key_id, key_size);
        if (!rsa) {
            EVP_PKEY_free(pkey);
            return NULL;
        }
        
        if (EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
            RSA_free(rsa);
            EVP_PKEY_free(pkey);
            return NULL;
        }
        RSA_free(rsa);
    } else if (alg == TEE_ALG_ECDSA_SHA256 || alg == TEE_ALG_ECDSA_SHA384) {
        int curve_nid = (alg == TEE_ALG_ECDSA_SHA256) ? NID_X9_62_prime256v1 : NID_secp384r1;
        EC_KEY *ec = keyless_engine_create_ec_key(key_id, curve_nid);
        if (!ec) {
            EVP_PKEY_free(pkey);
            return NULL;
        }
        
        if (EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
            EC_KEY_free(ec);
            EVP_PKEY_free(pkey);
            return NULL;
        }
        EC_KEY_free(ec);
    } else {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    printf("Keyless Engine: Created EVP_PKEY with engine backend\n");
    return pkey;
}

/**
 * 获取错误描述
 */
const char* keyless_engine_get_error_string(keyless_engine_result_t error) {
    switch (error) {
        case KEYLESS_ENGINE_SUCCESS:
            return "Success";
        case KEYLESS_ENGINE_ERROR_GENERIC:
            return "Generic error";
        case KEYLESS_ENGINE_ERROR_NOT_INITIALIZED:
            return "Engine not initialized";
        case KEYLESS_ENGINE_ERROR_INVALID_KEY:
            return "Invalid key";
        case KEYLESS_ENGINE_ERROR_TEE_ERROR:
            return "TEE error";
        default:
            return "Unknown error";
    }
}