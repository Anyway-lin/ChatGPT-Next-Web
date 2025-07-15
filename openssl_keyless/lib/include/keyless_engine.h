#ifndef KEYLESS_ENGINE_H
#define KEYLESS_ENGINE_H

#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "tee_sign.h"

// Engine ID和名称
#define KEYLESS_ENGINE_ID "keyless_tee"
#define KEYLESS_ENGINE_NAME "Keyless TEE Engine"

// Keyless Engine错误码
typedef enum {
    KEYLESS_ENGINE_SUCCESS = 0,
    KEYLESS_ENGINE_ERROR_GENERIC = 1,
    KEYLESS_ENGINE_ERROR_NOT_INITIALIZED = 2,
    KEYLESS_ENGINE_ERROR_INVALID_KEY = 3,
    KEYLESS_ENGINE_ERROR_TEE_ERROR = 4
} keyless_engine_result_t;

// Keyless私钥结构（用于ENGINE）
typedef struct {
    tee_key_handle_t *tee_handle;    // TEE密钥句柄
    tee_algorithm_t algorithm;        // 签名算法
    int key_size;                    // 密钥大小
    unsigned char *public_key_data;  // 公钥数据（DER格式）
    size_t public_key_len;           // 公钥长度
} keyless_engine_key_t;

/**
 * 初始化keyless ENGINE
 * @return 1成功，0失败
 */
int keyless_engine_init(void);

/**
 * 清理keyless ENGINE
 */
void keyless_engine_cleanup(void);

/**
 * 获取keyless ENGINE实例
 * @return ENGINE指针，失败返回NULL
 */
ENGINE* keyless_engine_get(void);

/**
 * 创建keyless RSA密钥
 * @param key_id TEE密钥ID
 * @param key_size 密钥大小
 * @return RSA密钥指针，失败返回NULL
 */
RSA* keyless_engine_create_rsa_key(uint32_t key_id, int key_size);

/**
 * 创建keyless EC密钥
 * @param key_id TEE密钥ID
 * @param curve_nid 椭圆曲线NID
 * @return EC_KEY指针，失败返回NULL
 */
EC_KEY* keyless_engine_create_ec_key(uint32_t key_id, int curve_nid);

/**
 * 创建keyless EVP_PKEY
 * @param key_id TEE密钥ID
 * @param alg TEE算法
 * @param key_size 密钥大小
 * @return EVP_PKEY指针，失败返回NULL
 */
EVP_PKEY* keyless_engine_create_evp_pkey(uint32_t key_id, tee_algorithm_t alg, int key_size);

/**
 * 获取错误描述
 * @param error 错误码
 * @return 错误描述字符串
 */
const char* keyless_engine_get_error_string(keyless_engine_result_t error);

#endif // KEYLESS_ENGINE_H