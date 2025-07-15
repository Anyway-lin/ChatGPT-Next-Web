#ifndef KEYLESS_PROVIDER_H
#define KEYLESS_PROVIDER_H

#include <openssl/provider.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>

#ifdef __cplusplus
extern "C" {
#endif

// Provider名称
#define KEYLESS_PROVIDER_NAME "keyless_tee"

/**
 * Provider初始化函数
 */
int keyless_provider_init(const OSSL_CORE_HANDLE *handle,
                         const OSSL_DISPATCH *in,
                         const OSSL_DISPATCH **out,
                         void **provctx);

/**
 * 加载Keyless Provider到OpenSSL
 * @param device_key_path 设备私钥路径
 * @return 成功返回OSSL_PROVIDER指针，失败返回NULL
 */
OSSL_PROVIDER *load_keyless_provider(const char *device_key_path);

/**
 * 卸载Keyless Provider
 */
void unload_keyless_provider(OSSL_PROVIDER *prov);

/**
 * 创建Keyless上下文的EVP_PKEY
 * @return 成功返回EVP_PKEY指针，失败返回NULL
 */
EVP_PKEY *create_keyless_pkey(void);

#ifdef __cplusplus
}
#endif

#endif // KEYLESS_PROVIDER_H