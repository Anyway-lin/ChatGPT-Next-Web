#ifndef TEE_PROVIDER_H
#define TEE_PROVIDER_H

#include <openssl/evp.h>

// TEE Provider相关函数
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx);

// 设置证书路径并构建TEE私钥
void tee_provider_set_certificate_path(const char *cert_path);

// 获取TEE构建的私钥
EVP_PKEY *tee_provider_get_private_key(void);

#endif // TEE_PROVIDER_H