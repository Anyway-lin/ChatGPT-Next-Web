#ifndef TEE_PROVIDER_H
#define TEE_PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/params.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* TEE Provider 错误代码 */
#define TEE_R_INVALID_KEY           100
#define TEE_R_OPERATION_FAILED      101
#define TEE_R_NOT_SUPPORTED         102
#define TEE_R_INVALID_DIGEST        103

/* TEE Provider 名称和版本 */
#define TEE_PROVIDER_NAME           "tee-provider"
#define TEE_PROVIDER_VERSION        "1.0.0"

/* TEE密钥结构 */
typedef struct tee_key_st {
    int key_type;               /* 密钥类型 (EVP_PKEY_RSA等) */
    int key_size;               /* 密钥长度 */
    EVP_PKEY *pkey;            /* OpenSSL私钥对象 */
    char *key_id;              /* 密钥标识符 */
    int ref_count;             /* 引用计数 */
} TEE_KEY;

/* TEE Provider上下文 */
typedef struct tee_provider_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    char *provname;
} TEE_PROVIDER_CTX;

/* TEE签名上下文 */
typedef struct tee_signature_ctx_st {
    TEE_PROVIDER_CTX *provctx;
    TEE_KEY *key;
    const EVP_MD *md;
    EVP_MD_CTX *mdctx;
    int operation;
} TEE_SIGNATURE_CTX;

/* TEE密钥管理上下文 */
typedef struct tee_keymgmt_ctx_st {
    TEE_PROVIDER_CTX *provctx;
    TEE_KEY *key;
} TEE_KEYMGMT_CTX;

/* 函数声明 */

/* Provider核心函数 */
int tee_provider_init(const OSSL_CORE_HANDLE *handle, 
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx);
int tee_provider_teardown(void *provctx);
const OSSL_DISPATCH *tee_provider_query_operation(void *provctx,
                                                   int operation_id,
                                                   int *no_cache);

/* 密钥管理函数 */
void *tee_keymgmt_new(void *provctx);
void tee_keymgmt_free(void *keydata);
int tee_keymgmt_has(const void *keydata, int selection);
int tee_keymgmt_match(const void *keydata1, const void *keydata2, int selection);
void *tee_keymgmt_load(const void *reference, size_t reference_sz);
void *tee_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[]);
int tee_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[]);
void *tee_keymgmt_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg);
void tee_keymgmt_gen_cleanup(void *genctx);

/* 签名函数 */
void *tee_signature_newctx(void *provctx, const char *propq);
void tee_signature_freectx(void *ctx);
int tee_signature_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[]);
int tee_signature_sign(void *ctx, unsigned char *sig, size_t *siglen,
                       size_t sigsize, const unsigned char *tbs, size_t tbslen);
int tee_signature_verify_init(void *ctx, void *provkey, const OSSL_PARAM params[]);
int tee_signature_verify(void *ctx, const unsigned char *sig, size_t siglen,
                         const unsigned char *tbs, size_t tbslen);
int tee_signature_digest_sign_init(void *ctx, const char *mdname, void *provkey,
                                   const OSSL_PARAM params[]);
int tee_signature_digest_sign_update(void *ctx, const unsigned char *data, size_t datalen);
int tee_signature_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize);

/* 工具函数 */
TEE_KEY *tee_key_new(void);
void tee_key_free(TEE_KEY *key);
TEE_KEY *tee_key_dup(const TEE_KEY *src);
int tee_key_up_ref(TEE_KEY *key);
int tee_load_private_key_from_file(const char *filename, TEE_KEY **key);
int tee_simulate_secure_operation(TEE_KEY *key, const unsigned char *data, 
                                  size_t data_len, unsigned char **result, size_t *result_len);

/* 调试和日志函数 */
void tee_log_debug(const char *format, ...);
void tee_log_error(const char *format, ...);

#endif /* TEE_PROVIDER_H */