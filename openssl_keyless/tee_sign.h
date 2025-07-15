#ifndef TEE_SIGN_H
#define TEE_SIGN_H

#include <stdint.h>
#include <stddef.h>

// TEE签名算法类型
typedef enum {
    TEE_ALG_RSA_PSS_SHA256 = 1,
    TEE_ALG_RSA_PKCS1_SHA256 = 2,
    TEE_ALG_ECDSA_SHA256 = 3,
    TEE_ALG_ECDSA_SHA384 = 4,
    TEE_ALG_ECDSA_SHA512 = 5
} tee_algorithm_t;

// TEE密钥句柄结构
typedef struct {
    uint32_t key_id;        // 密钥ID
    tee_algorithm_t alg;    // 签名算法
    uint32_t key_size;      // 密钥大小（位）
    uint8_t *public_key;    // 公钥数据
    size_t public_key_len;  // 公钥长度
} tee_key_handle_t;

// TEE错误码
typedef enum {
    TEE_SUCCESS = 0,
    TEE_ERROR_GENERIC = 1,
    TEE_ERROR_BAD_PARAMETERS = 2,
    TEE_ERROR_ITEM_NOT_FOUND = 3,
    TEE_ERROR_OUT_OF_MEMORY = 4,
    TEE_ERROR_COMMUNICATION = 5,
    TEE_ERROR_SECURITY = 6
} tee_result_t;

/**
 * 初始化TEE环境
 * @return TEE_SUCCESS 成功，其他值表示错误
 */
tee_result_t tee_init(void);

/**
 * 清理TEE环境
 */
void tee_cleanup(void);

/**
 * 创建密钥句柄
 * @param key_id 密钥ID
 * @param alg 签名算法
 * @param key_size 密钥大小（位）
 * @param handle 输出密钥句柄
 * @return TEE_SUCCESS 成功，其他值表示错误
 */
tee_result_t tee_create_key_handle(uint32_t key_id, tee_algorithm_t alg, 
                                  uint32_t key_size, tee_key_handle_t **handle);

/**
 * 销毁密钥句柄
 * @param handle 密钥句柄
 */
void tee_destroy_key_handle(tee_key_handle_t *handle);

/**
 * 使用TEE进行签名
 * @param handle 密钥句柄
 * @param data 待签名数据
 * @param data_len 数据长度
 * @param signature 输出签名缓冲区
 * @param signature_len 输入：缓冲区大小，输出：实际签名长度
 * @return TEE_SUCCESS 成功，其他值表示错误
 */
tee_result_t tee_sign(tee_key_handle_t *handle, const uint8_t *data, 
                     size_t data_len, uint8_t *signature, size_t *signature_len);

/**
 * 获取公钥
 * @param handle 密钥句柄
 * @param public_key 输出公钥缓冲区
 * @param public_key_len 输入：缓冲区大小，输出：实际公钥长度
 * @return TEE_SUCCESS 成功，其他值表示错误
 */
tee_result_t tee_get_public_key(tee_key_handle_t *handle, uint8_t *public_key, 
                               size_t *public_key_len);

/**
 * 获取签名算法名称
 * @param alg 签名算法
 * @return 算法名称字符串
 */
const char* tee_get_algorithm_name(tee_algorithm_t alg);

#endif // TEE_SIGN_H