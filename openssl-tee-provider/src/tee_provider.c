#include "tee_provider.h"

/* 全局Provider上下文 */
static tee_provider_ctx_t *g_provider_ctx = NULL;

/* 工具函数：打印错误信息 */
void tee_print_error(const char *func, const char *msg) {
    fprintf(stderr, "[TEE Provider] %s: %s\n", func, msg);
    ERR_print_errors_fp(stderr);
}

/* Provider查询函数 */
static const OSSL_ALGORITHM *tee_provider_query(void *provctx, int operation_id,
                                               int *no_cache) {
    *no_cache = 0;
    
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:
        /* 密钥交换算法 */
        return NULL; /* 暂不支持 */
    case OSSL_OP_SIGNATURE:
        /* 签名算法 */
        return NULL; /* 将在后续实现 */
    case OSSL_OP_CIPHER:
        /* 加密算法 */
        return NULL; /* 将在后续实现 */
    case OSSL_OP_DIGEST:
        /* 摘要算法，使用默认实现 */
        return NULL;
    default:
        return NULL;
    }
}

/* Provider功能函数 */
static const char *tee_provider_name(void *provctx) {
    return TEE_PROVIDER_NAME;
}

static const char *tee_provider_version(void *provctx) {
    return TEE_PROVIDER_VERSION;
}

static int tee_provider_self_test(void *provctx) {
    tee_provider_ctx_t *ctx = (tee_provider_ctx_t *)provctx;
    
    if (!ctx) {
        tee_print_error(__func__, "Invalid provider context");
        return 0;
    }
    
    printf("[TEE Provider] Self test passed\n");
    return 1;
}

static int tee_provider_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TEE_PROVIDER_NAME))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TEE_PROVIDER_VERSION))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "TEE Provider for OpenSSL 3.0.9"))
        return 0;
    
    return 1;
}

static const OSSL_PARAM *tee_provider_gettable_params(void *provctx) {
    static const OSSL_PARAM known_gettable_params[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
        OSSL_PARAM_END
    };
    return known_gettable_params;
}

/* Provider功能分发表 */
const OSSL_DISPATCH tee_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))tee_provider_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))tee_provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))tee_provider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))tee_provider_query },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))NULL },
    { OSSL_FUNC_PROVIDER_SELF_TEST, (void (*)(void))tee_provider_self_test },
    { 0, NULL }
};

/* Provider初始化函数 */
int tee_provider_init(const OSSL_CORE_HANDLE *handle,
                     const OSSL_DISPATCH *in,
                     const OSSL_DISPATCH **out,
                     void **provctx) {
    tee_provider_ctx_t *ctx;
    
    printf("[TEE Provider] Initializing...\n");
    
    /* 分配Provider上下文 */
    ctx = malloc(sizeof(tee_provider_ctx_t));
    if (!ctx) {
        tee_print_error(__func__, "Failed to allocate provider context");
        return 0;
    }
    
    memset(ctx, 0, sizeof(tee_provider_ctx_t));
    
    /* 初始化上下文 */
    ctx->libctx = OSSL_LIB_CTX_new();
    if (!ctx->libctx) {
        tee_print_error(__func__, "Failed to create library context");
        free(ctx);
        return 0;
    }
    
    ctx->provider_name = TEE_PROVIDER_NAME;
    ctx->keystore = sk_new_null();
    if (!ctx->keystore) {
        tee_print_error(__func__, "Failed to create keystore");
        OSSL_LIB_CTX_free(ctx->libctx);
        free(ctx);
        return 0;
    }
    
    /* 设置TEE接口函数指针 */
    ctx->tee_sign_func = tee_mock_sign;
    ctx->tee_verify_func = tee_mock_verify;
    ctx->tee_encrypt_func = tee_mock_encrypt;
    ctx->tee_decrypt_func = tee_mock_decrypt;
    
    /* 加载证书 */
    if (tee_load_certificates(ctx, "./certs") != 1) {
        printf("[TEE Provider] Warning: Failed to load certificates\n");
    }
    
    *provctx = ctx;
    *out = tee_provider_functions;
    g_provider_ctx = ctx;
    
    printf("[TEE Provider] Initialized successfully\n");
    return 1;
}

/* Provider清理函数 */
void tee_provider_teardown(void *provctx) {
    tee_provider_ctx_t *ctx = (tee_provider_ctx_t *)provctx;
    
    if (!ctx) {
        return;
    }
    
    printf("[TEE Provider] Tearing down...\n");
    
    /* 清理密钥存储 */
    if (ctx->keystore) {
        int num = sk_num(ctx->keystore);
        for (int i = 0; i < num; i++) {
            tee_keystore_entry_t *entry = (tee_keystore_entry_t *)sk_value(ctx->keystore, i);
            if (entry) {
                if (entry->cert) {
                    X509_free(entry->cert);
                }
                if (entry->cert_chain) {
                    sk_X509_pop_free(entry->cert_chain, X509_free);
                }
                free(entry);
            }
        }
        sk_free(ctx->keystore);
    }
    
    /* 清理库上下文 */
    if (ctx->libctx) {
        OSSL_LIB_CTX_free(ctx->libctx);
    }
    
    free(ctx);
    g_provider_ctx = NULL;
    
    printf("[TEE Provider] Teardown completed\n");
}

/* 加载证书文件 */
int tee_load_certificates(tee_provider_ctx_t *ctx, const char *cert_dir) {
    char cert_path[256];
    FILE *fp;
    X509 *cert;
    tee_keystore_entry_t *entry;
    
    if (!ctx || !cert_dir) {
        return 0;
    }
    
    /* 加载设备证书 */
    snprintf(cert_path, sizeof(cert_path), "%s/device_cert.pem", cert_dir);
    fp = fopen(cert_path, "r");
    if (fp) {
        cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);
        
        if (cert) {
            entry = malloc(sizeof(tee_keystore_entry_t));
            if (entry) {
                memset(entry, 0, sizeof(tee_keystore_entry_t));
                entry->key_info.key_id = 1;
                entry->key_info.key_type = TEE_KEY_TYPE_RSA;
                entry->key_info.key_size = 2048;
                strcpy(entry->key_info.key_label, "device_key");
                entry->cert = cert;
                entry->cert_chain = sk_X509_new_null();
                
                sk_push(ctx->keystore, entry);
                printf("[TEE Provider] Loaded device certificate\n");
            } else {
                X509_free(cert);
            }
        }
    }
    
    /* 加载根证书 */
    snprintf(cert_path, sizeof(cert_path), "%s/root_cert.pem", cert_dir);
    fp = fopen(cert_path, "r");
    if (fp) {
        cert = PEM_read_X509(fp, NULL, NULL, NULL);
        fclose(fp);
        
        if (cert) {
            /* 将根证书添加到设备证书链中 */
            if (sk_num(ctx->keystore) > 0) {
                entry = (tee_keystore_entry_t *)sk_value(ctx->keystore, 0);
                if (entry && entry->cert_chain) {
                    sk_X509_push(entry->cert_chain, cert);
                    printf("[TEE Provider] Added root certificate to chain\n");
                }
            }
        }
    }
    
    return 1;
}

/* 从证书创建公钥 */
EVP_PKEY *tee_create_public_key_from_cert(X509 *cert) {
    if (!cert) {
        return NULL;
    }
    
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (!pkey) {
        tee_print_error(__func__, "Failed to extract public key from certificate");
        return NULL;
    }
    
    return pkey;
}

/* 获取Provider上下文 */
tee_provider_ctx_t *tee_get_provider_context(void) {
    return g_provider_ctx;
}

/* Provider入口点 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx) {
    return tee_provider_init(handle, in, out, provctx);
}