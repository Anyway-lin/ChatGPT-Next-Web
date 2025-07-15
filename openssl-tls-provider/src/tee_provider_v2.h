#ifndef TEE_PROVIDER_V2_H
#define TEE_PROVIDER_V2_H

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <stdarg.h>

// TEE Provider V2 - 完全无私钥文件的安全实现

// Provider初始化函数
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, 
                      const OSSL_DISPATCH **out, void **provctx);

/**
 * 配置TEE Provider
 * @param cert_path 证书文件路径（用于提取公钥参数）
 * @return 1 成功，0 失败
 */
int tee_provider_configure(const char *cert_path);

/**
 * 创建与TEE Provider绑定的密钥对象
 * 私钥永远不会加载到内存中，只通过TEE接口访问
 * @param libctx OpenSSL库上下文
 * @return EVP_PKEY对象（绑定到TEE Provider）或NULL
 */
EVP_PKEY *tee_provider_create_key(OSSL_LIB_CTX *libctx);

#endif // TEE_PROVIDER_V2_H