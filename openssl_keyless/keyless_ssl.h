#ifndef KEYLESS_SSL_H
#define KEYLESS_SSL_H

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include "tee_sign.h"

// keyless SSL错误码
typedef enum {
    KEYLESS_SUCCESS = 0,
    KEYLESS_ERROR_GENERIC = 1,
    KEYLESS_ERROR_BAD_PARAMETERS = 2,
    KEYLESS_ERROR_OUT_OF_MEMORY = 3,
    KEYLESS_ERROR_TEE_ERROR = 4,
    KEYLESS_ERROR_SSL_ERROR = 5
} keyless_result_t;

// keyless私钥结构
typedef struct {
    tee_key_handle_t *tee_handle;  // TEE密钥句柄
    EVP_PKEY *public_key;          // 公钥
    int key_type;                  // 密钥类型 (EVP_PKEY_RSA 或 EVP_PKEY_EC)
    int key_size;                  // 密钥大小
} keyless_pkey_t;

/**
 * 初始化keyless SSL环境
 * @return KEYLESS_SUCCESS 成功，其他值表示错误
 */
keyless_result_t keyless_ssl_init(void);

/**
 * 清理keyless SSL环境
 */
void keyless_ssl_cleanup(void);

/**
 * 创建keyless私钥对象
 * @param key_id TEE密钥ID
 * @param alg TEE签名算法
 * @param key_size 密钥大小（位）
 * @param pkey 输出EVP_PKEY对象
 * @return KEYLESS_SUCCESS 成功，其他值表示错误
 */
keyless_result_t keyless_create_private_key(uint32_t key_id, 
                                           tee_algorithm_t alg,
                                           uint32_t key_size, 
                                           EVP_PKEY **pkey);

/**
 * 创建自签名证书（用于测试）
 * @param pkey 私钥对象
 * @param subject 证书主题
 * @param days 有效期（天）
 * @param cert 输出X509证书
 * @return KEYLESS_SUCCESS 成功，其他值表示错误
 */
keyless_result_t keyless_create_self_signed_cert(EVP_PKEY *pkey,
                                                 const char *subject,
                                                 int days,
                                                 X509 **cert);

/**
 * 为SSL上下文配置keyless证书和私钥
 * @param ctx SSL上下文
 * @param cert 证书
 * @param pkey 私钥
 * @return KEYLESS_SUCCESS 成功，其他值表示错误
 */
keyless_result_t keyless_ssl_use_certificate_and_key(SSL_CTX *ctx,
                                                     X509 *cert,
                                                     EVP_PKEY *pkey);

/**
 * 创建keyless SSL服务器
 * @param port 监听端口
 * @param cert 服务器证书
 * @param pkey 服务器私钥
 * @return SSL_CTX指针，失败返回NULL
 */
SSL_CTX* keyless_create_ssl_server(int port, X509 *cert, EVP_PKEY *pkey);

/**
 * 创建keyless SSL客户端
 * @return SSL_CTX指针，失败返回NULL
 */
SSL_CTX* keyless_create_ssl_client(void);

/**
 * 验证keyless签名
 * @param pkey 公钥
 * @param data 原始数据
 * @param data_len 数据长度
 * @param signature 签名数据
 * @param signature_len 签名长度
 * @param alg 签名算法
 * @return 1 验证成功，0 验证失败
 */
int keyless_verify_signature(EVP_PKEY *pkey, 
                            const unsigned char *data, 
                            size_t data_len,
                            const unsigned char *signature, 
                            size_t signature_len,
                            tee_algorithm_t alg);

/**
 * 打印keyless统计信息
 */
void keyless_print_stats(void);

/**
 * 获取错误描述
 * @param error 错误码
 * @return 错误描述字符串
 */
const char* keyless_get_error_string(keyless_result_t error);

#endif // KEYLESS_SSL_H