#ifndef TEE_PROVIDER_H
#define TEE_PROVIDER_H

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

// TEE Provider相关函数
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx);

// 设置TEE密钥ID和证书路径（不加载私钥到内存）
void tee_provider_set_certificate_path(const char *cert_path);

// 创建与TEE provider关联的密钥引用（私钥保护在TEE中）
EVP_PKEY *tee_provider_create_key_reference(OSSL_LIB_CTX *libctx);

#endif // TEE_PROVIDER_H