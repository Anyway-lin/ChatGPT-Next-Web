#ifndef TEE_PROVIDER_H
#define TEE_PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Provider名称 */
#define TEE_PROVIDER_NAME "tee_provider"
#define TEE_PROVIDER_VERSION "1.0.0"

/* 错误代码定义 */
#define TEE_ERROR_BASE                100
#define TEE_ERROR_INVALID_PARAM      (TEE_ERROR_BASE + 1)
#define TEE_ERROR_MEMORY_ALLOC       (TEE_ERROR_BASE + 2)
#define TEE_ERROR_TEE_OPERATION      (TEE_ERROR_BASE + 3)
#define TEE_ERROR_CERT_INVALID       (TEE_ERROR_BASE + 4)
#define TEE_ERROR_KEY_NOT_FOUND      (TEE_ERROR_BASE + 5)

/* TEE接口类型定义 */
typedef enum {
    TEE_ALG_RSA_PKCS1_V1_5 = 1,
    TEE_ALG_RSA_PSS,
    TEE_ALG_ECDSA_P256,
    TEE_ALG_ECDSA_P384,
    TEE_ALG_AES_GCM,
    TEE_ALG_AES_CBC
} tee_algorithm_t;

typedef enum {
    TEE_KEY_TYPE_RSA = 1,
    TEE_KEY_TYPE_EC,
    TEE_KEY_TYPE_AES
} tee_key_type_t;

typedef struct {
    uint32_t key_id;
    tee_key_type_t key_type;
    uint32_t key_size;
    char key_label[64];
} tee_key_info_t;

/* TEE密钥存储结构 */
typedef struct {
    tee_key_info_t key_info;
    X509 *cert;
    STACK_OF(X509) *cert_chain;
    void *tee_handle;
} tee_keystore_entry_t;

/* TEE Provider上下文 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    const char *provider_name;
    STACK_OF(tee_keystore_entry_t) *keystore;
    int (*tee_sign_func)(const unsigned char *data, size_t data_len,
                        unsigned char *sig, size_t *sig_len,
                        uint32_t key_id, tee_algorithm_t alg);
    int (*tee_verify_func)(const unsigned char *data, size_t data_len,
                          const unsigned char *sig, size_t sig_len,
                          uint32_t key_id, tee_algorithm_t alg);
    int (*tee_encrypt_func)(const unsigned char *plaintext, size_t plaintext_len,
                           unsigned char *ciphertext, size_t *ciphertext_len,
                           uint32_t key_id, tee_algorithm_t alg,
                           const unsigned char *iv, size_t iv_len);
    int (*tee_decrypt_func)(const unsigned char *ciphertext, size_t ciphertext_len,
                           unsigned char *plaintext, size_t *plaintext_len,
                           uint32_t key_id, tee_algorithm_t alg,
                           const unsigned char *iv, size_t iv_len);
} tee_provider_ctx_t;

/* TEE密钥管理结构 */
typedef struct {
    tee_provider_ctx_t *provider_ctx;
    uint32_t key_id;
    tee_key_type_t key_type;
    EVP_PKEY *public_key;
    X509 *cert;
} tee_key_ctx_t;

/* TEE签名上下文 */
typedef struct {
    tee_provider_ctx_t *provider_ctx;
    tee_key_ctx_t *key_ctx;
    tee_algorithm_t algorithm;
    EVP_MD_CTX *md_ctx;
} tee_signature_ctx_t;

/* TEE加密上下文 */
typedef struct {
    tee_provider_ctx_t *provider_ctx;
    tee_key_ctx_t *key_ctx;
    tee_algorithm_t algorithm;
    unsigned char iv[16];
    size_t iv_len;
    int encrypt;
} tee_cipher_ctx_t;

/* Provider函数声明 */
extern const OSSL_DISPATCH tee_provider_functions[];

/* Provider初始化和清理 */
int tee_provider_init(const OSSL_CORE_HANDLE *handle,
                     const OSSL_DISPATCH *in,
                     const OSSL_DISPATCH **out,
                     void **provctx);
void tee_provider_teardown(void *provctx);

/* 密钥管理函数 */
tee_keystore_entry_t *tee_keystore_load_entry(tee_provider_ctx_t *ctx,
                                              uint32_t key_id);
int tee_keystore_add_entry(tee_provider_ctx_t *ctx,
                          const tee_keystore_entry_t *entry);
tee_key_ctx_t *tee_key_new(tee_provider_ctx_t *provider_ctx);
void tee_key_free(tee_key_ctx_t *key_ctx);
int tee_key_load_from_tee(tee_key_ctx_t *key_ctx, uint32_t key_id);

/* 签名函数 */
tee_signature_ctx_t *tee_signature_new(tee_provider_ctx_t *provider_ctx);
void tee_signature_free(tee_signature_ctx_t *sig_ctx);
int tee_signature_init(tee_signature_ctx_t *sig_ctx,
                      tee_key_ctx_t *key_ctx,
                      tee_algorithm_t algorithm);
int tee_signature_update(tee_signature_ctx_t *sig_ctx,
                        const unsigned char *data,
                        size_t data_len);
int tee_signature_final(tee_signature_ctx_t *sig_ctx,
                       unsigned char *sig,
                       size_t *sig_len);

/* 加密函数 */
tee_cipher_ctx_t *tee_cipher_new(tee_provider_ctx_t *provider_ctx);
void tee_cipher_free(tee_cipher_ctx_t *cipher_ctx);
int tee_cipher_init(tee_cipher_ctx_t *cipher_ctx,
                   tee_key_ctx_t *key_ctx,
                   tee_algorithm_t algorithm,
                   int encrypt);
int tee_cipher_update(tee_cipher_ctx_t *cipher_ctx,
                     unsigned char *out,
                     size_t *out_len,
                     const unsigned char *in,
                     size_t in_len);
int tee_cipher_final(tee_cipher_ctx_t *cipher_ctx,
                    unsigned char *out,
                    size_t *out_len);

/* TEE接口模拟函数 */
int tee_mock_sign(const unsigned char *data, size_t data_len,
                 unsigned char *sig, size_t *sig_len,
                 uint32_t key_id, tee_algorithm_t alg);
int tee_mock_verify(const unsigned char *data, size_t data_len,
                   const unsigned char *sig, size_t sig_len,
                   uint32_t key_id, tee_algorithm_t alg);
int tee_mock_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *ciphertext, size_t *ciphertext_len,
                    uint32_t key_id, tee_algorithm_t alg,
                    const unsigned char *iv, size_t iv_len);
int tee_mock_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                    unsigned char *plaintext, size_t *plaintext_len,
                    uint32_t key_id, tee_algorithm_t alg,
                    const unsigned char *iv, size_t iv_len);

/* 工具函数 */
void tee_print_error(const char *func, const char *msg);
int tee_load_certificates(tee_provider_ctx_t *ctx, const char *cert_dir);
EVP_PKEY *tee_create_public_key_from_cert(X509 *cert);

/* SSL回调函数 */
int tee_client_cert_cb(SSL *ssl, X509 **x509, EVP_PKEY **pkey);
int tee_cert_verify_cb(X509_STORE_CTX *ctx, void *arg);

#endif /* TEE_PROVIDER_H */