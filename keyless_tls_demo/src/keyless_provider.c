#include "keyless_provider.h"
#include "tee_mock.h"
#include <openssl/provider.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Provider上下文结构
typedef struct {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    char *device_key_path;
} KEYLESS_PROVCTX;

// 密钥管理上下文
typedef struct {
    KEYLESS_PROVCTX *provctx;
    EVP_PKEY *pubkey;  // 公钥部分
    int key_size;      // 密钥长度
} KEYLESS_KEY;

// 签名上下文
typedef struct {
    KEYLESS_PROVCTX *provctx;
    KEYLESS_KEY *key;
    const EVP_MD *md;
    int pad_mode;
} KEYLESS_SIG_CTX;

// 前向声明
static const OSSL_DISPATCH keyless_rsa_signature_functions[];
static const OSSL_DISPATCH keyless_rsa_asymcipher_functions[];
static const OSSL_DISPATCH keyless_rsa_keymgmt_functions[];

// Provider查询函数表
static const OSSL_ALGORITHM keyless_algorithms[] = {
    {"RSA", "provider=keyless_tee", keyless_rsa_keymgmt_functions, "Keyless RSA Key Management"},
    {"RSA", "provider=keyless_tee", keyless_rsa_signature_functions, "Keyless RSA Signature"},
    {"RSA", "provider=keyless_tee", keyless_rsa_asymcipher_functions, "Keyless RSA Asymmetric Cipher"},
    {NULL, NULL, NULL, NULL}
};

// Provider操作查询函数
static const OSSL_ALGORITHM *keyless_query_operation(void *provctx, int operation_id, int *no_cache) {
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
    case OSSL_OP_SIGNATURE:
    case OSSL_OP_ASYM_CIPHER:
        return keyless_algorithms;
    }
    return NULL;
}

// Provider核心函数
static void keyless_teardown(void *provctx) {
    KEYLESS_PROVCTX *ctx = (KEYLESS_PROVCTX *)provctx;
    if (ctx) {
        if (ctx->device_key_path) {
            free(ctx->device_key_path);
        }
        TeeCleanup();
        free(ctx);
    }
}

static const OSSL_PARAM *keyless_gettable_params(void *provctx) {
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static int keyless_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, KEYLESS_PROVIDER_NAME))
        return 0;
        
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0.0"))
        return 0;
        
    return 1;
}

// Provider分发表
static const OSSL_DISPATCH keyless_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))keyless_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))keyless_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))keyless_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))keyless_query_operation },
    { 0, NULL }
};

// 密钥管理函数实现
static void *keyless_keymgmt_new(void *provctx) {
    KEYLESS_KEY *key = malloc(sizeof(KEYLESS_KEY));
    if (key != NULL) {
        memset(key, 0, sizeof(KEYLESS_KEY));
        key->provctx = (KEYLESS_PROVCTX *)provctx;
    }
    return key;
}

static void keyless_keymgmt_free(void *keydata) {
    KEYLESS_KEY *key = (KEYLESS_KEY *)keydata;
    if (key) {
        if (key->pubkey) {
            EVP_PKEY_free(key->pubkey);
        }
        free(key);
    }
}

static int keyless_keymgmt_has(const void *keydata, int selection) {
    const KEYLESS_KEY *key = (const KEYLESS_KEY *)keydata;
    if (key == NULL) return 0;
    
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && key->pubkey != NULL)
        return 1;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 1; // 我们假设总是有私钥（在TEE中）
        
    return 0;
}

static int keyless_keymgmt_match(const void *keydata1, const void *keydata2, int selection) {
    // 简化实现
    return keydata1 == keydata2;
}

// 密钥管理函数表
static const OSSL_DISPATCH keyless_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))keyless_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))keyless_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))keyless_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))keyless_keymgmt_match },
    { 0, NULL }
};

// 签名操作函数实现
static void *keyless_signature_newctx(void *provctx, const char *propq) {
    KEYLESS_SIG_CTX *ctx = malloc(sizeof(KEYLESS_SIG_CTX));
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(KEYLESS_SIG_CTX));
        ctx->provctx = (KEYLESS_PROVCTX *)provctx;
    }
    return ctx;
}

static void keyless_signature_freectx(void *ctx) {
    KEYLESS_SIG_CTX *sigctx = (KEYLESS_SIG_CTX *)ctx;
    if (sigctx) {
        free(sigctx);
    }
}

static int keyless_signature_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[]) {
    KEYLESS_SIG_CTX *sigctx = (KEYLESS_SIG_CTX *)ctx;
    KEYLESS_KEY *key = (KEYLESS_KEY *)provkey;
    
    if (sigctx == NULL || key == NULL) return 0;
    
    sigctx->key = key;
    sigctx->md = EVP_sha256(); // 默认使用SHA256
    sigctx->pad_mode = RSA_PKCS1_PADDING;
    
    return 1;
}

static int keyless_signature_sign(void *ctx, unsigned char *sig, size_t *siglen,
                                 size_t sigsize, const unsigned char *tbs, size_t tbslen) {
    KEYLESS_SIG_CTX *sigctx = (KEYLESS_SIG_CTX *)ctx;
    struct TeeBlob inData, outData;
    int ret;
    
    if (sigctx == NULL || sigctx->key == NULL) return 0;
    
    // 准备输入数据
    inData.data = (uint8_t *)tbs;
    inData.dataLength = tbslen;
    
    // 初始化输出数据
    memset(&outData, 0, sizeof(outData));
    
    // 调用TEE签名函数
    ret = TeeKeylessOperation(KM_PURPOSE_SIGN, KM_PAD_RSA_PKCS1_1_5_SIGN, &inData, &outData);
    if (ret != 0) {
        return 0;
    }
    
    // 检查输出缓冲区大小
    if (sig == NULL) {
        *siglen = outData.dataLength;
        free(outData.data);
        return 1;
    }
    
    if (sigsize < outData.dataLength) {
        free(outData.data);
        return 0;
    }
    
    // 复制签名数据
    memcpy(sig, outData.data, outData.dataLength);
    *siglen = outData.dataLength;
    
    free(outData.data);
    return 1;
}

// 签名函数表
static const OSSL_DISPATCH keyless_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))keyless_signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))keyless_signature_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))keyless_signature_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))keyless_signature_sign },
    { 0, NULL }
};

// 非对称加密操作函数实现
static void *keyless_asym_cipher_newctx(void *provctx) {
    KEYLESS_SIG_CTX *ctx = malloc(sizeof(KEYLESS_SIG_CTX));
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(KEYLESS_SIG_CTX));
        ctx->provctx = (KEYLESS_PROVCTX *)provctx;
    }
    return ctx;
}

static void keyless_asym_cipher_freectx(void *ctx) {
    KEYLESS_SIG_CTX *cipherctx = (KEYLESS_SIG_CTX *)ctx;
    if (cipherctx) {
        free(cipherctx);
    }
}

static int keyless_asym_cipher_decrypt_init(void *ctx, void *provkey, const OSSL_PARAM params[]) {
    KEYLESS_SIG_CTX *cipherctx = (KEYLESS_SIG_CTX *)ctx;
    KEYLESS_KEY *key = (KEYLESS_KEY *)provkey;
    
    if (cipherctx == NULL || key == NULL) return 0;
    
    cipherctx->key = key;
    cipherctx->pad_mode = RSA_PKCS1_PADDING; // 默认填充模式
    
    return 1;
}

static int keyless_asym_cipher_decrypt(void *ctx, unsigned char *out, size_t *outlen,
                                      size_t outsize, const unsigned char *in, size_t inlen) {
    KEYLESS_SIG_CTX *cipherctx = (KEYLESS_SIG_CTX *)ctx;
    struct TeeBlob inData, outData;
    int ret;
    
    if (cipherctx == NULL || cipherctx->key == NULL) return 0;
    
    // 准备输入数据
    inData.data = (uint8_t *)in;
    inData.dataLength = inlen;
    
    // 初始化输出数据
    memset(&outData, 0, sizeof(outData));
    
    // 调用TEE解密函数
    ret = TeeKeylessOperation(KM_PURPOSE_DECRYPT, KM_PAD_RSA_PKCS1_1_5_ENCRYPT, &inData, &outData);
    if (ret != 0) {
        return 0;
    }
    
    // 检查输出缓冲区大小
    if (out == NULL) {
        *outlen = outData.dataLength;
        free(outData.data);
        return 1;
    }
    
    if (outsize < outData.dataLength) {
        free(outData.data);
        return 0;
    }
    
    // 复制解密数据
    memcpy(out, outData.data, outData.dataLength);
    *outlen = outData.dataLength;
    
    free(outData.data);
    return 1;
}

// 非对称加密函数表
static const OSSL_DISPATCH keyless_rsa_asymcipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))keyless_asym_cipher_newctx },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))keyless_asym_cipher_freectx },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))keyless_asym_cipher_decrypt_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))keyless_asym_cipher_decrypt },
    { 0, NULL }
};

// Provider初始化函数
int keyless_provider_init(const OSSL_CORE_HANDLE *handle,
                         const OSSL_DISPATCH *in,
                         const OSSL_DISPATCH **out,
                         void **provctx) {
    KEYLESS_PROVCTX *ctx;
    
    ctx = malloc(sizeof(KEYLESS_PROVCTX));
    if (ctx == NULL) return 0;
    
    memset(ctx, 0, sizeof(KEYLESS_PROVCTX));
    ctx->handle = handle;
    
    *provctx = ctx;
    *out = keyless_provider_functions;
    
    return 1;
}

// 辅助函数实现
OSSL_PROVIDER *load_keyless_provider(const char *device_key_path) {
    OSSL_PROVIDER *prov;
    
    // 初始化TEE模拟环境
    if (TeeInit(device_key_path) != 0) {
        fprintf(stderr, "Failed to initialize TEE mock\n");
        return NULL;
    }
    
    // 加载provider
    prov = OSSL_PROVIDER_load(NULL, KEYLESS_PROVIDER_NAME);
    if (prov == NULL) {
        fprintf(stderr, "Failed to load keyless provider\n");
        TeeCleanup();
        return NULL;
    }
    
    return prov;
}

void unload_keyless_provider(OSSL_PROVIDER *prov) {
    if (prov) {
        OSSL_PROVIDER_unload(prov);
    }
    TeeCleanup();
}

EVP_PKEY *create_keyless_pkey(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    
    // 创建密钥上下文
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", KEYLESS_PROVIDER_NAME);
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create keyless key context\n");
        return NULL;
    }
    
    // 生成密钥（实际上是创建一个引用TEE的密钥）
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize key generation\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate keyless key\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}