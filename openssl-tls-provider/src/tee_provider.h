#ifndef TEE_PROVIDER_H
#define TEE_PROVIDER_H

#include <openssl/core.h>
#include <openssl/provider.h>

// TEE Provider函数声明
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx);
void tee_provider_set_private_key_path(const char *path);

#endif // TEE_PROVIDER_H