#ifndef KEYLESS_EVP_H
#define KEYLESS_EVP_H

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 创建一个keyless EVP_PKEY对象
 * 该对象包含公钥信息，但所有私钥操作都重定向到TEE接口
 * 
 * @param public_key_pem_file 包含公钥信息的私钥文件路径（仅用于提取公钥）
 * @return 成功返回EVP_PKEY指针，失败返回NULL
 */
EVP_PKEY *create_keyless_evp_pkey(const char *public_key_pem_file);

/**
 * 初始化keyless EVP环境
 * @return 0成功，其他值表示错误
 */
int keyless_evp_init(void);

/**
 * 清理keyless EVP环境
 */
void keyless_evp_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // KEYLESS_EVP_H