#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>

/* Provider名称和版本 */
#define TEE_PROVIDER_NAME "tee-provider"
#define TEE_PROVIDER_VERSION "1.0.0"

/* 全局变量存储私钥 */
static EVP_PKEY *g_device_private_key = NULL;
static const OSSL_CORE_HANDLE *g_core_handle = NULL;

/* 错误处理函数 */
static void tee_provider_error(const char *msg) {
    fprintf(stderr, "TEE Provider Error: %s\n", msg);
}

/* TEE模拟：签名操作 */
static int tee_sign_operation(const unsigned char *tbs, size_t tbslen,
                             unsigned char *sig, size_t *siglen) {
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;
    
    printf("TEE Provider: 执行签名操作 (数据长度: %zu)\n", tbslen);
    
    if (!g_device_private_key) {
        tee_provider_error("设备私钥未加载");
        return 0;
    }
    
    ctx = EVP_PKEY_CTX_new(g_device_private_key, NULL);
    if (!ctx) {
        tee_provider_error("创建PKEY上下文失败");
        return 0;
    }
    
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        tee_provider_error("初始化签名操作失败");
        goto end;
    }
    
    /* 设置签名填充模式为PKCS1 */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        tee_provider_error("设置RSA填充模式失败");
        goto end;
    }
    
    /* 执行签名 */
    if (EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen) <= 0) {
        tee_provider_error("签名操作失败");
        goto end;
    }
    
    printf("TEE Provider: 签名成功 (签名长度: %zu)\n", *siglen);
    ret = 1;
    
end:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* TEE模拟：解密操作 */
static int tee_decrypt_operation(const unsigned char *in, size_t inlen,
                                unsigned char *out, size_t *outlen) {
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;
    
    printf("TEE Provider: 执行解密操作 (数据长度: %zu)\n", inlen);
    
    if (!g_device_private_key) {
        tee_provider_error("设备私钥未加载");
        return 0;
    }
    
    ctx = EVP_PKEY_CTX_new(g_device_private_key, NULL);
    if (!ctx) {
        tee_provider_error("创建PKEY上下文失败");
        return 0;
    }
    
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        tee_provider_error("初始化解密操作失败");
        goto end;
    }
    
    /* 设置解密填充模式 */
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        tee_provider_error("设置RSA填充模式失败");
        goto end;
    }
    
    /* 执行解密 */
    if (EVP_PKEY_decrypt(ctx, out, outlen, in, inlen) <= 0) {
        tee_provider_error("解密操作失败");
        goto end;
    }
    
    printf("TEE Provider: 解密成功 (输出长度: %zu)\n", *outlen);
    ret = 1;
    
end:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* 加载设备私钥到TEE Provider */
int tee_provider_load_private_key(const char *key_file) {
    FILE *fp = NULL;
    
    printf("TEE Provider: 加载私钥文件 %s\n", key_file);
    
    fp = fopen(key_file, "r");
    if (!fp) {
        tee_provider_error("无法打开私钥文件");
        return 0;
    }
    
    g_device_private_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!g_device_private_key) {
        tee_provider_error("读取私钥失败");
        return 0;
    }
    
    printf("TEE Provider: 私钥加载成功\n");
    return 1;
}

/* ========== Provider Signature Implementation ========== */

typedef struct {
    EVP_PKEY *pubkey;
    int pad_mode;
} TEE_SIG_CTX;

static void *tee_signature_newctx(void *provctx, const char *propq) {
    TEE_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(TEE_SIG_CTX));
    if (ctx != NULL) {
        ctx->pad_mode = RSA_PKCS1_PADDING;
        printf("TEE Provider: 创建签名上下文\n");
    }
    return ctx;
}

static void tee_signature_freectx(void *ctx) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    if (sigctx) {
        EVP_PKEY_free(sigctx->pubkey);
        OPENSSL_free(sigctx);
        printf("TEE Provider: 释放签名上下文\n");
    }
}

static int tee_signature_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[]) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    
    printf("TEE Provider: 初始化签名操作\n");
    
    if (!sigctx || !provkey) {
        return 0;
    }
    
    /* 在实际TEE实现中，这里不需要存储私钥，只需要验证公钥 */
    EVP_PKEY_up_ref((EVP_PKEY *)provkey);
    sigctx->pubkey = (EVP_PKEY *)provkey;
    
    return 1;
}

static int tee_signature_sign(void *ctx, unsigned char *sig, size_t *siglen,
                             size_t sigsize, const unsigned char *tbs, size_t tbslen) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    
    printf("TEE Provider: 执行签名 (待签名数据长度: %zu)\n", tbslen);
    
    if (!sigctx) {
        return 0;
    }
    
    /* 调用TEE签名操作 */
    return tee_sign_operation(tbs, tbslen, sig, siglen);
}

static int tee_signature_verify_init(void *ctx, void *provkey, const OSSL_PARAM params[]) {
    /* 验证操作不需要私钥，可以直接使用公钥 */
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    
    printf("TEE Provider: 初始化验证操作\n");
    
    if (!sigctx || !provkey) {
        return 0;
    }
    
    EVP_PKEY_up_ref((EVP_PKEY *)provkey);
    sigctx->pubkey = (EVP_PKEY *)provkey;
    
    return 1;
}

static int tee_signature_verify(void *ctx, const unsigned char *sig, size_t siglen,
                               const unsigned char *tbs, size_t tbslen) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    EVP_PKEY_CTX *pctx = NULL;
    int ret = 0;
    
    printf("TEE Provider: 执行验证 (签名长度: %zu, 数据长度: %zu)\n", siglen, tbslen);
    
    if (!sigctx || !sigctx->pubkey) {
        return 0;
    }
    
    pctx = EVP_PKEY_CTX_new(sigctx->pubkey, NULL);
    if (!pctx) {
        return 0;
    }
    
    if (EVP_PKEY_verify_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(pctx, sigctx->pad_mode) <= 0 ||
        EVP_PKEY_verify(pctx, sig, siglen, tbs, tbslen) <= 0) {
        goto end;
    }
    
    ret = 1;
    printf("TEE Provider: 验证成功\n");
    
end:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/* Signature函数表 */
static const OSSL_DISPATCH tee_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))tee_signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))tee_signature_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))tee_signature_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))tee_signature_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))tee_signature_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))tee_signature_verify },
    { 0, NULL }
};

/* ========== Provider Key Management ========== */

typedef struct {
    EVP_PKEY *key;
} TEE_KEY;

static void *tee_keymgmt_new(void *provctx) {
    TEE_KEY *key = OPENSSL_zalloc(sizeof(TEE_KEY));
    printf("TEE Provider: 创建密钥管理对象\n");
    return key;
}

static void tee_keymgmt_free(void *keydata) {
    TEE_KEY *key = (TEE_KEY *)keydata;
    if (key) {
        EVP_PKEY_free(key->key);
        OPENSSL_free(key);
        printf("TEE Provider: 释放密钥管理对象\n");
    }
}

static int tee_keymgmt_has(const void *keydata, int selection) {
    const TEE_KEY *key = (const TEE_KEY *)keydata;
    return key && key->key;
}

static void *tee_keymgmt_load(const void *reference, size_t reference_sz) {
    TEE_KEY *key = NULL;
    
    printf("TEE Provider: 加载密钥引用\n");
    
    /* 在实际TEE实现中，这里会根据reference加载对应的密钥句柄 */
    if (!g_device_private_key) {
        return NULL;
    }
    
    key = OPENSSL_zalloc(sizeof(TEE_KEY));
    if (key) {
        EVP_PKEY_up_ref(g_device_private_key);
        key->key = g_device_private_key;
    }
    
    return key;
}

/* Key Management函数表 */
static const OSSL_DISPATCH tee_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tee_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))tee_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))tee_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))tee_keymgmt_load },
    { 0, NULL }
};

/* ========== Provider算法查询 ========== */

static const OSSL_ALGORITHM tee_algorithms[] = {
    { "RSA", "provider=tee-provider", tee_signature_functions, "TEE RSA Signature" },
    { "RSA", "provider=tee-provider", tee_keymgmt_functions, "TEE RSA Key Management" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *tee_query_operation(void *provctx, int operation_id,
                                                int *no_cache) {
    *no_cache = 0;
    
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        printf("TEE Provider: 查询签名算法\n");
        return tee_algorithms;
    case OSSL_OP_KEYMGMT:
        printf("TEE Provider: 查询密钥管理算法\n");
        return tee_algorithms;
    default:
        return NULL;
    }
}

/* ========== Provider参数 ========== */

static const OSSL_PARAM *tee_gettable_params(void *provctx) {
    static const OSSL_PARAM param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_END
    };
    return param_types;
}

static int tee_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TEE_PROVIDER_NAME))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TEE_PROVIDER_VERSION))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "TEE Provider for OpenSSL"))
        return 0;
    
    return 1;
}

/* ========== Provider主要函数表 ========== */

static const OSSL_DISPATCH tee_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))tee_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))tee_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))tee_query_operation },
    { 0, NULL }
};

/* ========== Provider初始化和清理 ========== */

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx) {
    printf("TEE Provider: 初始化\n");
    
    g_core_handle = handle;
    *out = tee_provider_functions;
    *provctx = (void *)handle;
    
    printf("TEE Provider: 初始化完成\n");
    return 1;
}

void tee_provider_cleanup(void) {
    printf("TEE Provider: 清理资源\n");
    if (g_device_private_key) {
        EVP_PKEY_free(g_device_private_key);
        g_device_private_key = NULL;
    }
}