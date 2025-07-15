#include "tee_provider.h"
#include <stdarg.h>
#include <pthread.h>

/* 全局变量 */
static pthread_mutex_t tee_mutex = PTHREAD_MUTEX_INITIALIZER;
static int tee_debug_enabled = 1;

/* 调试和日志函数 */
void tee_log_debug(const char *format, ...) {
    if (!tee_debug_enabled) return;
    
    va_list args;
    va_start(args, format);
    printf("[TEE-DEBUG] ");
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

void tee_log_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "[TEE-ERROR] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/* TEE密钥管理函数 */
TEE_KEY *tee_key_new(void) {
    TEE_KEY *key = malloc(sizeof(TEE_KEY));
    if (!key) return NULL;
    
    memset(key, 0, sizeof(TEE_KEY));
    key->ref_count = 1;
    key->key_id = strdup("tee-default-key");
    
    tee_log_debug("Created new TEE key: %p", key);
    return key;
}

void tee_key_free(TEE_KEY *key) {
    if (!key) return;
    
    pthread_mutex_lock(&tee_mutex);
    key->ref_count--;
    if (key->ref_count > 0) {
        pthread_mutex_unlock(&tee_mutex);
        return;
    }
    pthread_mutex_unlock(&tee_mutex);
    
    tee_log_debug("Freeing TEE key: %p", key);
    
    if (key->pkey) {
        EVP_PKEY_free(key->pkey);
    }
    if (key->key_id) {
        free(key->key_id);
    }
    free(key);
}

int tee_key_up_ref(TEE_KEY *key) {
    if (!key) return 0;
    
    pthread_mutex_lock(&tee_mutex);
    key->ref_count++;
    pthread_mutex_unlock(&tee_mutex);
    
    return 1;
}

TEE_KEY *tee_key_dup(const TEE_KEY *src) {
    if (!src) return NULL;
    
    TEE_KEY *dst = tee_key_new();
    if (!dst) return NULL;
    
    dst->key_type = src->key_type;
    dst->key_size = src->key_size;
    
    if (src->pkey) {
        EVP_PKEY_up_ref(src->pkey);
        dst->pkey = src->pkey;
    }
    
    if (src->key_id) {
        free(dst->key_id);
        dst->key_id = strdup(src->key_id);
    }
    
    return dst;
}

/* 从文件加载私钥到TEE环境中 */
int tee_load_private_key_from_file(const char *filename, TEE_KEY **key) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        tee_log_error("Cannot open key file: %s", filename);
        return 0;
    }
    
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!pkey) {
        tee_log_error("Cannot read private key from file: %s", filename);
        return 0;
    }
    
    TEE_KEY *tee_key = tee_key_new();
    if (!tee_key) {
        EVP_PKEY_free(pkey);
        return 0;
    }
    
    tee_key->pkey = pkey;
    tee_key->key_type = EVP_PKEY_id(pkey);
    tee_key->key_size = EVP_PKEY_bits(pkey);
    
    free(tee_key->key_id);
    tee_key->key_id = strdup(filename);
    
    *key = tee_key;
    tee_log_debug("Loaded private key from %s into TEE (type: %d, size: %d bits)", 
                  filename, tee_key->key_type, tee_key->key_size);
    
    return 1;
}

/* 模拟TEE安全操作 */
int tee_simulate_secure_operation(TEE_KEY *key, const unsigned char *data, 
                                  size_t data_len, unsigned char **result, size_t *result_len) {
    if (!key || !key->pkey || !data || !result || !result_len) {
        tee_log_error("Invalid parameters for TEE secure operation");
        return 0;
    }
    
    tee_log_debug("Performing secure operation in TEE for key: %s", key->key_id);
    
    /* 模拟TEE环境中的签名操作 */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key->pkey, NULL);
    if (!ctx) {
        tee_log_error("Failed to create EVP_PKEY_CTX");
        return 0;
    }
    
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        tee_log_error("Failed to initialize signing");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    /* 设置签名填充模式 */
    if (key->key_type == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
            tee_log_error("Failed to set RSA padding");
            EVP_PKEY_CTX_free(ctx);
            return 0;
        }
    }
    
    /* 获取签名长度 */
    size_t sig_len;
    if (EVP_PKEY_sign(ctx, NULL, &sig_len, data, data_len) <= 0) {
        tee_log_error("Failed to get signature length");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    /* 分配签名缓冲区 */
    unsigned char *sig = malloc(sig_len);
    if (!sig) {
        tee_log_error("Failed to allocate signature buffer");
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    /* 执行签名 */
    if (EVP_PKEY_sign(ctx, sig, &sig_len, data, data_len) <= 0) {
        tee_log_error("Failed to perform signature");
        free(sig);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    *result = sig;
    *result_len = sig_len;
    
    tee_log_debug("TEE secure operation completed successfully, signature size: %zu", sig_len);
    return 1;
}

/* Provider核心函数 */
static OSSL_FUNC_provider_get_params_fn tee_provider_get_params;
static OSSL_FUNC_provider_gettable_params_fn tee_provider_gettable_params;

/* Provider参数 */
static const OSSL_PARAM tee_provider_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static int tee_provider_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TEE_PROVIDER_NAME))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TEE_PROVIDER_VERSION))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "TEE Provider Demo Build"))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;
    
    return 1;
}

static const OSSL_PARAM *tee_provider_gettable_params(void *provctx) {
    return tee_provider_param_types;
}

/* 密钥管理操作 - 函数已在头文件中声明 */

void *tee_keymgmt_new(void *provctx) {
    tee_log_debug("Creating new TEE keymgmt context");
    return tee_key_new();
}

void tee_keymgmt_free(void *keydata) {
    tee_log_debug("Freeing TEE keymgmt keydata: %p", keydata);
    tee_key_free((TEE_KEY *)keydata);
}

int tee_keymgmt_has(const void *keydata, int selection) {
    const TEE_KEY *key = (const TEE_KEY *)keydata;
    
    if (!key || !key->pkey) return 0;
    
    int ok = 0;
    
    /* 检查密钥类型是否支持 */
    int key_type = EVP_PKEY_id(key->pkey);
    if (key_type == EVP_PKEY_RSA || key_type == EVP_PKEY_RSA_PSS) {
        if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
            /* 检查是否有私钥组件 */
            if (EVP_PKEY_get_size(key->pkey) > 0) {
                ok = 1;
            }
        }
        
        if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
            /* 检查是否有公钥组件 */
            if (EVP_PKEY_get_size(key->pkey) > 0) {
                ok = 1;
            }
        }
    }
    
    tee_log_debug("TEE keymgmt has check: selection=%d, result=%d", selection, ok);
    return ok;
}

int tee_keymgmt_match(const void *keydata1, const void *keydata2, int selection) {
    const TEE_KEY *key1 = (const TEE_KEY *)keydata1;
    const TEE_KEY *key2 = (const TEE_KEY *)keydata2;
    
    if (!key1 || !key2) return 0;
    
    int match = EVP_PKEY_eq(key1->pkey, key2->pkey);
    tee_log_debug("TEE keymgmt match: %d", match);
    return match;
}

void *tee_keymgmt_load(const void *reference, size_t reference_sz) {
    if (!reference || reference_sz == 0) {
        tee_log_error("Invalid reference in keymgmt_load");
        return NULL;
    }
    
    const char *filename = (const char *)reference;
    TEE_KEY *key = NULL;
    
    tee_log_debug("Loading TEE key from reference: %.*s", (int)reference_sz, filename);
    
    if (tee_load_private_key_from_file(filename, &key)) {
        tee_log_debug("Successfully loaded key: %p", key);
        return key;
    }
    
    tee_log_error("Failed to load key from file");
    return NULL;
}

/* 签名操作 - 函数已在头文件中声明 */

void *tee_signature_newctx(void *provctx, const char *propq) {
    TEE_SIGNATURE_CTX *ctx;
    
    if (!provctx) {
        tee_log_error("Invalid provider context in signature_newctx");
        return NULL;
    }
    
    ctx = malloc(sizeof(TEE_SIGNATURE_CTX));
    if (!ctx) {
        tee_log_error("Failed to allocate signature context");
        return NULL;
    }
    
    memset(ctx, 0, sizeof(TEE_SIGNATURE_CTX));
    ctx->provctx = (TEE_PROVIDER_CTX *)provctx;
    
    tee_log_debug("Created new TEE signature context: %p", ctx);
    return ctx;
}

void tee_signature_freectx(void *ctx) {
    TEE_SIGNATURE_CTX *sctx = (TEE_SIGNATURE_CTX *)ctx;
    if (!sctx) return;
    
    tee_log_debug("Freeing TEE signature context: %p", ctx);
    
    if (sctx->key) {
        tee_key_free(sctx->key);
    }
    if (sctx->mdctx) {
        EVP_MD_CTX_free(sctx->mdctx);
    }
    free(sctx);
}

int tee_signature_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[]) {
    TEE_SIGNATURE_CTX *sctx = (TEE_SIGNATURE_CTX *)ctx;
    TEE_KEY *key = (TEE_KEY *)provkey;
    
    if (!sctx) {
        tee_log_error("Invalid signature context for sign init");
        return 0;
    }
    
    if (!key) {
        tee_log_error("Invalid key for sign init");
        return 0;
    }
    
    if (!key->pkey) {
        tee_log_error("Key has no EVP_PKEY for sign init");
        return 0;
    }
    
    if (sctx->key) {
        tee_key_free(sctx->key);
        sctx->key = NULL;
    }
    
    sctx->key = key;
    tee_key_up_ref(key);
    sctx->operation = EVP_PKEY_OP_SIGN;
    
    tee_log_debug("TEE signature sign init completed for key: %s", 
                  key->key_id ? key->key_id : "unknown");
    return 1;
}

int tee_signature_sign(void *ctx, unsigned char *sig, size_t *siglen,
                       size_t sigsize, const unsigned char *tbs, size_t tbslen) {
    TEE_SIGNATURE_CTX *sctx = (TEE_SIGNATURE_CTX *)ctx;
    
    if (!sctx) {
        tee_log_error("Invalid signature context for sign");
        return 0;
    }
    
    if (!sctx->key) {
        tee_log_error("No key in signature context for sign");
        return 0;
    }
    
    if (!siglen) {
        tee_log_error("Invalid siglen pointer");
        return 0;
    }
    
    if (!tbs || tbslen == 0) {
        tee_log_error("Invalid data to be signed");
        return 0;
    }
    
    unsigned char *result = NULL;
    size_t result_len = 0;
    
    tee_log_debug("Starting TEE signature operation");
    
    /* 在TEE环境中执行签名操作 */
    if (!tee_simulate_secure_operation(sctx->key, tbs, tbslen, &result, &result_len)) {
        tee_log_error("TEE secure operation failed");
        return 0;
    }
    
    if (sig == NULL) {
        /* 只返回需要的长度 */
        *siglen = result_len;
        free(result);
        tee_log_debug("Returning signature length: %zu", result_len);
        return 1;
    }
    
    if (sigsize < result_len) {
        tee_log_error("Signature buffer too small: need %zu, got %zu", result_len, sigsize);
        free(result);
        return 0;
    }
    
    memcpy(sig, result, result_len);
    *siglen = result_len;
    free(result);
    
    tee_log_debug("TEE signature sign completed, signature size: %zu", result_len);
    return 1;
}

int tee_signature_digest_sign_init(void *ctx, const char *mdname, void *provkey,
                                   const OSSL_PARAM params[]) {
    TEE_SIGNATURE_CTX *sctx = (TEE_SIGNATURE_CTX *)ctx;
    
    if (!tee_signature_sign_init(ctx, provkey, params)) {
        return 0;
    }
    
    if (mdname) {
        sctx->md = EVP_MD_fetch(sctx->provctx->libctx, mdname, NULL);
        if (!sctx->md) {
            tee_log_error("Cannot fetch digest: %s", mdname);
            return 0;
        }
        
        sctx->mdctx = EVP_MD_CTX_new();
        if (!sctx->mdctx) {
            EVP_MD_free((EVP_MD *)sctx->md);
            return 0;
        }
        
        if (EVP_DigestInit_ex(sctx->mdctx, sctx->md, NULL) <= 0) {
            EVP_MD_CTX_free(sctx->mdctx);
            EVP_MD_free((EVP_MD *)sctx->md);
            return 0;
        }
    }
    
    tee_log_debug("TEE digest sign init completed with digest: %s", mdname ? mdname : "none");
    return 1;
}

int tee_signature_digest_sign_update(void *ctx, const unsigned char *data, size_t datalen) {
    TEE_SIGNATURE_CTX *sctx = (TEE_SIGNATURE_CTX *)ctx;
    
    if (!sctx || !sctx->mdctx) {
        tee_log_error("Invalid context for digest sign update");
        return 0;
    }
    
    if (EVP_DigestUpdate(sctx->mdctx, data, datalen) <= 0) {
        tee_log_error("Failed to update digest");
        return 0;
    }
    
    return 1;
}

int tee_signature_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize) {
    TEE_SIGNATURE_CTX *sctx = (TEE_SIGNATURE_CTX *)ctx;
    
    if (!sctx || !sctx->mdctx) {
        tee_log_error("Invalid context for digest sign final");
        return 0;
    }
    
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    
    if (EVP_DigestFinal_ex(sctx->mdctx, digest, &digest_len) <= 0) {
        tee_log_error("Failed to finalize digest");
        return 0;
    }
    
    return tee_signature_sign(ctx, sig, siglen, sigsize, digest, digest_len);
}

/* 密钥管理和签名操作分发表 */
static const OSSL_DISPATCH tee_keymgmt_rsa_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tee_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))tee_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))tee_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))tee_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))tee_keymgmt_load },
    { 0, NULL }
};

/* 简化的signature operations - 暂时只提供基本功能 */
static const OSSL_DISPATCH tee_signature_rsa_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))tee_signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))tee_signature_freectx },
    { 0, NULL }
};

const OSSL_DISPATCH *tee_provider_query_operation(void *provctx, int operation_id, int *no_cache) {
    if (!provctx || !no_cache) {
        tee_log_error("Invalid parameters in query_operation");
        return NULL;
    }
    
    *no_cache = 0;
    
    tee_log_debug("Query operation called for operation_id: %d", operation_id);
    
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        tee_log_debug("Keymgmt operations requested but not supported yet");
        return NULL;  /* 暂时禁用keymgmt operations */
    case OSSL_OP_SIGNATURE:
        tee_log_debug("Signature operations requested but not supported yet");
        return NULL;  /* 暂时禁用signature operations */
    default:
        tee_log_debug("Unsupported operation: %d", operation_id);
        return NULL;
    }
}

int tee_provider_teardown(void *provctx) {
    TEE_PROVIDER_CTX *ctx = (TEE_PROVIDER_CTX *)provctx;
    
    if (ctx) {
        tee_log_debug("Tearing down TEE provider context");
        if (ctx->provname) {
            free(ctx->provname);
        }
        free(ctx);
    }
    
    return 1;
}

/* Provider入口点 */
static const OSSL_DISPATCH tee_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))tee_provider_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))tee_provider_query_operation },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))tee_provider_get_params },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))tee_provider_gettable_params },
    { 0, NULL }
};

int tee_provider_init(const OSSL_CORE_HANDLE *handle, 
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx) {
    TEE_PROVIDER_CTX *ctx;
    
    tee_log_debug("Initializing TEE Provider");
    
    ctx = malloc(sizeof(TEE_PROVIDER_CTX));
    if (!ctx) {
        tee_log_error("Failed to allocate provider context");
        return 0;
    }
    
    memset(ctx, 0, sizeof(TEE_PROVIDER_CTX));
    ctx->handle = handle;
    ctx->provname = strdup(TEE_PROVIDER_NAME);
    
    /* 获取库上下文 */
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            {
                OSSL_FUNC_core_get_libctx_fn *get_libctx = OSSL_FUNC_core_get_libctx(in);
                /* 修复指针类型不兼容问题 */
                OPENSSL_CORE_CTX *core_ctx = get_libctx(handle);
                ctx->libctx = (OSSL_LIB_CTX *)core_ctx;
            }
            break;
        default:
            break;
        }
    }
    
    *out = tee_provider_functions;
    *provctx = ctx;
    
    tee_log_debug("TEE Provider initialized successfully");
    return 1;
}