#ifndef KEYLESS_SSL_CALLBACK_H
#define KEYLESS_SSL_CALLBACK_H

#include <openssl/ssl.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 初始化keyless SSL回调系统
 * @param device_key_path 设备私钥文件路径（仅用于提取公钥）
 * @param device_cert_path 设备证书文件路径
 * @return 0成功，其他值表示错误
 */
int keyless_ssl_callback_init(const char *device_key_path, const char *device_cert_path);

/**
 * 设置SSL上下文的keyless回调
 * @param ctx SSL上下文
 * @return 0成功，其他值表示错误
 */
int keyless_ssl_set_callback(SSL_CTX *ctx);

/**
 * 清理keyless SSL回调系统
 */
void keyless_ssl_callback_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // KEYLESS_SSL_CALLBACK_H