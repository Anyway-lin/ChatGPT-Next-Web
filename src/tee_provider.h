#ifndef TEE_PROVIDER_H
#define TEE_PROVIDER_H

#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/types.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// TEE算法类型枚举
typedef enum {
    TEE_ALG_RSA_PKCS1_V1_5,
    TEE_ALG_RSA_PSS,
    TEE_ALG_ECDSA_P256,
    TEE_ALG_ECDSA_P384,
    TEE_ALG_AES_GCM_128,
    TEE_ALG_AES_GCM_256,
    TEE_ALG_AES_CBC_128,
    TEE_ALG_AES_CBC_256
} TEE_Algorithm;

// 密钥类型枚举
typedef enum {
    TEE_KEY_TYPE_RSA_2048,
    TEE_KEY_TYPE_RSA_3072,
    TEE_KEY_TYPE_RSA_4096,
    TEE_KEY_TYPE_ECC_P256,
    TEE_KEY_TYPE_ECC_P384,
    TEE_KEY_TYPE_AES_128,
    TEE_KEY_TYPE_AES_256
} TEE_KeyType;

// TEE接口结构体
typedef struct {
    // 初始化和清理
    int (*init)(void);
    void (*cleanup)(void);
    int (*self_test)(void);
    
    // 密钥管理
    int (*generate_key)(TEE_KeyType key_type, uint32_t *key_id);
    int (*import_key)(TEE_KeyType key_type, const uint8_t *key_data, 
                      size_t key_len, uint32_t *key_id);
    int (*export_public_key)(uint32_t key_id, uint8_t *pub_key, 
                             size_t *pub_key_len);
    int (*delete_key)(uint32_t key_id);
    
    // 签名和验证
    int (*sign)(uint32_t key_id, TEE_Algorithm alg, 
                const uint8_t *hash, size_t hash_len,
                uint8_t *signature, size_t *sig_len);
    int (*verify)(uint32_t key_id, TEE_Algorithm alg,
                  const uint8_t *hash, size_t hash_len,
                  const uint8_t *signature, size_t sig_len);
    
    // 加密和解密
    int (*encrypt)(uint32_t key_id, TEE_Algorithm alg,
                   const uint8_t *plaintext, size_t plain_len,
                   uint8_t *ciphertext, size_t *cipher_len,
                   const uint8_t *iv, size_t iv_len);
    int (*decrypt)(uint32_t key_id, TEE_Algorithm alg,
                   const uint8_t *ciphertext, size_t cipher_len,
                   uint8_t *plaintext, size_t *plain_len,
                   const uint8_t *iv, size_t iv_len);
    
    // 密钥导出（用于证书关联）
    int (*get_key_info)(uint32_t key_id, TEE_KeyType *key_type, 
                        size_t *key_bits);
} TEE_Interface;

// 前向声明
typedef struct TEE_PROV_CTX_st TEE_PROV_CTX;

// TEE Provider 上下文结构（完整定义在.c文件中）
typedef struct TEE_PROV_CTX_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    
    // 核心函数指针
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx;
    OSSL_FUNC_core_new_error_fn *c_new_error;
    OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
    OSSL_FUNC_core_vset_error_fn *c_vset_error;
} TEE_PROV_CTX;

// Provider 主要函数声明
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx);

// TEE接口初始化
int tee_interface_init(void);

// Provider内部函数
void tee_provider_set_error(int reason, const char *fmt, ...);
TEE_PROV_CTX *tee_provider_get_ctx(void);

// 算法实现声明
extern const OSSL_ALGORITHM tee_signature_algorithms[];
extern const OSSL_ALGORITHM tee_keymgmt_algorithms[];

// 签名算法实现函数
void *tee_signature_newctx(void *provctx, const char *propq);
int tee_signature_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[]);
int tee_signature_sign(void *ctx, unsigned char *sig, size_t *siglen,
                       size_t sigsize, const unsigned char *tbs, size_t tbslen);
int tee_signature_verify_init(void *ctx, void *provkey, const OSSL_PARAM params[]);
int tee_signature_verify(void *ctx, const unsigned char *sig, size_t siglen,
                         const unsigned char *tbs, size_t tbslen);
void tee_signature_freectx(void *ctx);
void *tee_signature_dupctx(void *ctx);
int tee_signature_get_ctx_params(void *ctx, OSSL_PARAM *params);
const OSSL_PARAM *tee_signature_gettable_ctx_params(void *ctx, void *provctx);
int tee_signature_set_ctx_params(void *ctx, const OSSL_PARAM params[]);
const OSSL_PARAM *tee_signature_settable_ctx_params(void *ctx, void *provctx);

// 密钥管理函数
void *tee_keymgmt_new(void *provctx);
void tee_keymgmt_free(void *keydata);
int tee_keymgmt_has(const void *keydata, int selection);
int tee_keymgmt_match(const void *keydata1, const void *keydata2, int selection);
int tee_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[]);
int tee_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg);
const OSSL_PARAM *tee_keymgmt_import_types(int selection);
const OSSL_PARAM *tee_keymgmt_export_types(int selection);

// 错误码定义
#define TEE_ERR_INVALID_PARAMETER   1
#define TEE_ERR_MEMORY_ALLOCATION   2
#define TEE_ERR_TEE_OPERATION       3
#define TEE_ERR_KEY_NOT_FOUND       4
#define TEE_ERR_ALGORITHM_MISMATCH  5

// TEE Provider特有的参数名称
#define OSSL_PKEY_PARAM_TEE_KEY_ID  "tee-key-id"

#ifdef __cplusplus
}
#endif

#endif /* TEE_PROVIDER_H */