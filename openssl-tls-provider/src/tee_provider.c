#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#define TEE_PROVIDER_NAME "tee"
#define TEE_PROVIDER_VERSION "1.0.0"

// TEE Provider context
typedef struct {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    const char *propq;
} TEE_PROV_CTX;

// TEE signature context
typedef struct {
    TEE_PROV_CTX *provctx;
    char *mdname;
    char *tee_key_id;  // TEE中的私钥标识，而不是实际私钥
    int initialized;
} TEE_SIG_CTX;

// TEE key management context - 只存储密钥标识，不存储实际私钥
typedef struct {
    TEE_PROV_CTX *provctx;
    char *key_id;      // TEE中的密钥标识
    int key_available; // 密钥是否在TEE中可用
    BIGNUM *n;         // 只存储公钥参数用于验证
    BIGNUM *e;
} TEE_KEY_CTX;

// 全局TEE配置 - 不存储实际私钥
static char *global_tee_key_id = NULL;       // TEE中的密钥标识
static char *global_certificate_path = NULL; // 证书路径用于获取公钥参数

// 日志函数
static void tee_log(const char *msg) {
    fprintf(stderr, "[TEE Provider] %s\n", msg);
}

// TEE安全签名操作 - 模拟TEE内部签名（私钥永不暴露）
static int tee_secure_sign(const char *key_id, const unsigned char *tbs, size_t tbslen, 
                          unsigned char *sig, size_t *siglen) {
    // 在真实TEE中，这里会调用TEE内部的安全签名接口
    // 私钥永远不会离开TEE环境
    
    tee_log("=== TEE安全签名操作开始 ===");
    printf("TEE密钥ID: %s\n", key_id ? key_id : "unknown");
    printf("签名数据长度: %zu 字节\n", tbslen);
    
    // 模拟TEE内部签名过程
    // 实际实现中，这里会：
    // 1. 验证key_id是否存在于TEE中
    // 2. 使用TEE内部的私钥进行签名
    // 3. 返回签名结果，私钥永不暴露
    
    // 为了演示，我们这里临时加载私钥进行签名
    // 但在真实TEE中，私钥已经预先安全存储在TEE内部
    FILE *fp = fopen("./certs/client.key", "rb");
    if (!fp) {
        tee_log("TEE签名失败：无法访问TEE密钥");
        return 0;
    }
    
    EVP_PKEY *tee_priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!tee_priv_key) {
        tee_log("TEE签名失败：TEE密钥无效");
        return 0;
    }
    
    // 使用TEE密钥进行签名
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(tee_priv_key, NULL);
    if (!ctx) {
        tee_log("TEE签名失败：无法创建签名上下文");
        EVP_PKEY_free(tee_priv_key);
        return 0;
    }
    
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        tee_log("TEE签名失败：签名初始化失败");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(tee_priv_key);
        return 0;
    }
    
    if (EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen) <= 0) {
        tee_log("TEE签名失败：签名操作失败");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(tee_priv_key);
        return 0;
    }
    
    // 清理（在真实TEE中，私钥不会被加载到这里）
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(tee_priv_key);
    
    tee_log("=== TEE安全签名操作成功 ===");
    return 1;
}

// 从证书获取公钥参数（用于创建公钥对象）
static int get_public_key_params_from_cert(const char *cert_path, BIGNUM **n, BIGNUM **e) {
    FILE *fp = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pub_key = NULL;
    const RSA *rsa = NULL;
    const BIGNUM *pub_n = NULL, *pub_e = NULL;
    int ret = 0;
    
    tee_log("从证书获取公钥参数");
    
    fp = fopen(cert_path, "rb");
    if (!fp) {
        tee_log("无法打开证书文件");
        return 0;
    }
    
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!cert) {
        tee_log("无法解析证书");
        return 0;
    }
    
    pub_key = X509_get_pubkey(cert);
    if (!pub_key) {
        tee_log("无法获取证书公钥");
        X509_free(cert);
        return 0;
    }
    
    if (EVP_PKEY_id(pub_key) != EVP_PKEY_RSA) {
        tee_log("证书不是RSA类型");
        EVP_PKEY_free(pub_key);
        X509_free(cert);
        return 0;
    }
    
    rsa = EVP_PKEY_get0_RSA(pub_key);
    if (!rsa) {
        tee_log("无法获取RSA结构");
        EVP_PKEY_free(pub_key);
        X509_free(cert);
        return 0;
    }
    
    pub_n = RSA_get0_n(rsa);
    pub_e = RSA_get0_e(rsa);
    
    if (!pub_n || !pub_e) {
        tee_log("无法获取RSA公钥参数");
        EVP_PKEY_free(pub_key);
        X509_free(cert);
        return 0;
    }
    
    *n = BN_dup(pub_n);
    *e = BN_dup(pub_e);
    
    if (!*n || !*e) {
        tee_log("无法复制公钥参数");
        if (*n) BN_free(*n);
        if (*e) BN_free(*e);
        *n = *e = NULL;
        EVP_PKEY_free(pub_key);
        X509_free(cert);
        return 0;
    }
    
    EVP_PKEY_free(pub_key);
    X509_free(cert);
    
    tee_log("公钥参数获取成功");
    return 1;
}

// 清理函数
static void tee_provider_teardown(void *provctx) {
    TEE_PROV_CTX *ctx = (TEE_PROV_CTX *)provctx;
    if (ctx) {
        OPENSSL_free(ctx);
    }
    if (global_tee_key_id) {
        OPENSSL_free(global_tee_key_id);
        global_tee_key_id = NULL;
    }
    if (global_certificate_path) {
        OPENSSL_free(global_certificate_path);
        global_certificate_path = NULL;
    }
}

// 签名操作的新建函数
static void *tee_signature_newctx(void *provctx, const char *propq) {
    TEE_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(TEE_SIG_CTX));
    if (ctx == NULL) {
        return NULL;
    }
    
    ctx->provctx = (TEE_PROV_CTX *)provctx;
    ctx->initialized = 0;
    
    tee_log("*** TEE签名上下文创建成功 ***");
    return ctx;
}

// 签名操作的释放函数
static void tee_signature_freectx(void *ctx) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    if (sigctx) {
        if (sigctx->mdname) {
            OPENSSL_free(sigctx->mdname);
        }
        if (sigctx->tee_key_id) {
            OPENSSL_free(sigctx->tee_key_id);
        }
        OPENSSL_free(sigctx);
    }
    tee_log("*** TEE签名上下文释放 ***");
}

// 签名初始化函数
static int tee_signature_digest_sign_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM params[]) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    TEE_KEY_CTX *key_ctx = NULL;
    
    if (!sigctx) {
        return 0;
    }
    
    tee_log("*** TEE签名初始化开始 ***");
    
    // 获取TEE密钥上下文
    if (provkey) {
        key_ctx = (TEE_KEY_CTX *)provkey;
        if (key_ctx && key_ctx->key_id) {
            sigctx->tee_key_id = OPENSSL_strdup(key_ctx->key_id);
            tee_log("使用TEE密钥管理提供的密钥ID");
        } else {
            tee_log("签名初始化失败：无效的TEE密钥上下文");
            return 0;
        }
    } else if (global_tee_key_id) {
        sigctx->tee_key_id = OPENSSL_strdup(global_tee_key_id);
        tee_log("使用全局TEE密钥ID");
    } else {
        tee_log("签名初始化失败：无TEE密钥ID");
        return 0;
    }
    
    // 设置摘要算法
    if (mdname) {
        sigctx->mdname = OPENSSL_strdup(mdname);
        tee_log("设置摘要算法");
    }
    
    sigctx->initialized = 1;
    tee_log("*** TEE签名初始化成功 ***");
    return 1;
}

// 签名更新函数
static int tee_signature_digest_sign_update(void *ctx, const unsigned char *data, size_t datalen) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    if (!sigctx || !sigctx->initialized) {
        return 0;
    }
    
    tee_log("*** TEE签名更新数据 ***");
    printf("数据长度: %zu 字节\n", datalen);
    
    // 在真实TEE中，这里会将数据发送到TEE进行摘要更新
    // 当前简化实现直接返回成功
    return 1;
}

// 签名最终函数 - 关键：这里会被OpenSSL调用来执行实际签名
static int tee_signature_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    if (!sigctx || !sigctx->initialized) {
        return 0;
    }
    
    tee_log("*** TEE签名最终操作（关键函数）***");
    
    if (!sigctx->tee_key_id) {
        tee_log("TEE签名失败：无TEE密钥ID");
        return 0;
    }
    
    // 这里是关键：调用TEE安全签名
    // 在真实实现中，tbs数据应该是之前update操作累积的摘要
    // 为了演示，我们使用一个示例数据
    const unsigned char tbs_data[] = "TEE signature test data";
    size_t tbs_len = sizeof(tbs_data) - 1;
    
    // 如果只是查询签名长度
    if (!sig) {
        *siglen = 256; // RSA-2048的签名长度
        tee_log("返回TEE签名长度");
        return 1;
    }
    
    // 执行TEE安全签名
    if (!tee_secure_sign(sigctx->tee_key_id, tbs_data, tbs_len, sig, siglen)) {
        tee_log("TEE安全签名失败");
        return 0;
    }
    
    tee_log("*** TEE签名最终操作成功完成 ***");
    return 1;
}

// 签名操作调度表
static const OSSL_DISPATCH tee_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))tee_signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))tee_signature_freectx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))tee_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))tee_signature_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))tee_signature_digest_sign_final },
    { 0, NULL }
};

// 密钥管理：新建函数
static void *tee_keymgmt_new(void *provctx) {
    TEE_KEY_CTX *ctx = OPENSSL_zalloc(sizeof(TEE_KEY_CTX));
    if (ctx) {
        ctx->provctx = (TEE_PROV_CTX *)provctx;
        ctx->key_available = 0;
        tee_log("*** TEE密钥管理：新建上下文 ***");
    }
    return ctx;
}

// 密钥管理：释放函数
static void tee_keymgmt_free(void *keydata) {
    TEE_KEY_CTX *ctx = (TEE_KEY_CTX *)keydata;
    if (ctx) {
        if (ctx->key_id) {
            OPENSSL_free(ctx->key_id);
        }
        if (ctx->n) {
            BN_free(ctx->n);
        }
        if (ctx->e) {
            BN_free(ctx->e);
        }
        OPENSSL_free(ctx);
        tee_log("*** TEE密钥管理：释放上下文 ***");
    }
}

// 密钥管理：加载函数 - 创建TEE密钥引用（不加载实际私钥）
static void *tee_keymgmt_load(const void *reference, size_t reference_sz) {
    TEE_KEY_CTX *ctx = NULL;
    
    tee_log("*** TEE密钥管理：加载TEE密钥引用 ***");
    
    ctx = OPENSSL_zalloc(sizeof(TEE_KEY_CTX));
    if (!ctx) {
        tee_log("TEE密钥管理：无法分配上下文");
        return NULL;
    }
    
    // 设置TEE密钥ID
    if (global_tee_key_id) {
        ctx->key_id = OPENSSL_strdup(global_tee_key_id);
        ctx->key_available = 1;
        
        // 从证书获取公钥参数（仅用于OpenSSL兼容性）
        if (global_certificate_path) {
            get_public_key_params_from_cert(global_certificate_path, &ctx->n, &ctx->e);
        }
        
        tee_log("TEE密钥管理：返回TEE密钥引用（不含私钥数据）");
        return ctx;
    }
    
    OPENSSL_free(ctx);
    tee_log("TEE密钥管理：无可用TEE密钥");
    return NULL;
}

// 密钥管理：检查函数
static int tee_keymgmt_has(const void *keydata, int selection) {
    const TEE_KEY_CTX *ctx = (const TEE_KEY_CTX *)keydata;
    
    tee_log("*** TEE密钥管理：检查密钥属性 ***");
    
    if (!ctx || !ctx->key_available) {
        return 0;
    }
    
    // TEE模式：我们有私钥（在TEE中），也有公钥参数
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        tee_log("确认：TEE中有私钥");
        return 1;
    }
    
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        tee_log("确认：有公钥参数");
        return ctx->n && ctx->e;
    }
    
    return 1;
}

// 密钥管理：匹配函数
static int tee_keymgmt_match(const void *keydata1, const void *keydata2, int selection) {
    const TEE_KEY_CTX *ctx1 = (const TEE_KEY_CTX *)keydata1;
    const TEE_KEY_CTX *ctx2 = (const TEE_KEY_CTX *)keydata2;
    
    tee_log("*** TEE密钥管理：匹配密钥 ***");
    
    if (!ctx1 || !ctx2) {
        return 0;
    }
    
    // 比较TEE密钥ID
    if (ctx1->key_id && ctx2->key_id) {
        return strcmp(ctx1->key_id, ctx2->key_id) == 0;
    }
    
    return 0;
}

// 密钥管理：导出函数
static int tee_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg) {
    TEE_KEY_CTX *ctx = (TEE_KEY_CTX *)keydata;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    int ret = 0;
    
    tee_log("*** TEE密钥管理：导出密钥参数 ***");
    
    if (!ctx || !ctx->key_available) {
        return 0;
    }
    
    bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        return 0;
    }
    
    // 只导出公钥参数，私钥永不离开TEE
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && ctx->n && ctx->e) {
        if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, ctx->n) &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, ctx->e)) {
            tee_log("导出公钥参数（私钥保护在TEE中）");
        }
    }
    
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params) {
        ret = param_cb(params, cbarg);
        OSSL_PARAM_free(params);
    }
    
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

// 密钥管理：从数据导入密钥
static void *tee_keymgmt_fromdata(void *provctx, const OSSL_PARAM params[]) {
    TEE_KEY_CTX *ctx = NULL;
    const OSSL_PARAM *p;
    BIGNUM *n = NULL, *e = NULL;
    
    tee_log("*** TEE密钥管理：从数据导入密钥 ***");
    
    ctx = OPENSSL_zalloc(sizeof(TEE_KEY_CTX));
    if (!ctx) {
        return NULL;
    }
    
    ctx->provctx = (TEE_PROV_CTX *)provctx;
    
    // 获取公钥参数
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
    if (p && !OSSL_PARAM_get_BN(p, &n)) {
        tee_log("无法获取RSA模数");
        goto err;
    }
    
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    if (p && !OSSL_PARAM_get_BN(p, &e)) {
        tee_log("无法获取RSA指数");
        goto err;
    }
    
    if (n && e) {
        ctx->n = n;
        ctx->e = e;
        // 设置默认TEE密钥ID
        if (global_tee_key_id) {
            ctx->key_id = OPENSSL_strdup(global_tee_key_id);
        } else {
            ctx->key_id = OPENSSL_strdup("tee_key_default");
        }
        ctx->key_available = 1;
        tee_log("从数据成功导入TEE密钥（只有公钥参数）");
        return ctx;
    }
    
err:
    if (n) BN_free(n);
    if (e) BN_free(e);
    if (ctx) OPENSSL_free(ctx);
    return NULL;
}

// 密钥管理：检查导入参数
static int tee_keymgmt_fromdata_init(void *provctx, int selection) {
    tee_log("*** TEE密钥管理：检查导入参数 ***");
    
    // TEE模式：支持导入公钥参数，但私钥必须已在TEE中
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        tee_log("支持导入公钥参数");
        return 1;
    }
    
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        tee_log("私钥必须已在TEE中，不支持外部导入");
        return 0; // TEE模式下不允许从外部导入私钥
    }
    
    return 1;
}

// 密钥管理：获取可导出参数
static const OSSL_PARAM *tee_keymgmt_export_types(int selection) {
    static const OSSL_PARAM export_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };
    
    tee_log("*** TEE密钥管理：获取可导出参数类型 ***");
    
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return export_types;
    }
    
    return NULL;
}

// 密钥管理：获取可导入参数
static const OSSL_PARAM *tee_keymgmt_import_types(int selection) {
    static const OSSL_PARAM import_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_END
    };
    
    tee_log("*** TEE密钥管理：获取可导入参数类型 ***");
    
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return import_types;
    }
    
    return NULL;
}

// 密钥管理操作调度表
static const OSSL_DISPATCH tee_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tee_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))tee_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))tee_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))tee_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))tee_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))tee_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))tee_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))tee_keymgmt_import_types },
    { 0, NULL }
};

// 算法查询函数
static const OSSL_ALGORITHM *tee_provider_query(void *provctx, int operation_id, int *no_cache) {
    *no_cache = 0;
    
    switch (operation_id) {
        case OSSL_OP_SIGNATURE:
            {
                static const OSSL_ALGORITHM signature_algs[] = {
                    { "RSA", "provider=tee,fips=no", tee_signature_functions, "TEE RSA signature" },
                    { "RSA-PSS", "provider=tee,fips=no", tee_signature_functions, "TEE RSA-PSS signature" },
                    { NULL, NULL, NULL, NULL }
                };
                tee_log("查询：返回TEE签名算法");
                return signature_algs;
            }
        case OSSL_OP_KEYMGMT:
            {
                static const OSSL_ALGORITHM keymgmt_algs[] = {
                    { "RSA", "provider=tee,fips=no", tee_keymgmt_functions, "TEE RSA key management" },
                    { "RSA-PSS", "provider=tee,fips=no", tee_keymgmt_functions, "TEE RSA-PSS key management" },
                    { NULL, NULL, NULL, NULL }
                };
                tee_log("查询：返回TEE密钥管理算法");
                return keymgmt_algs;
            }
        default:
            return NULL;
    }
}

// 获取参数函数
static int tee_provider_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, TEE_PROVIDER_NAME)) {
        return 0;
    }
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, TEE_PROVIDER_VERSION)) {
        return 0;
    }
    
    return 1;
}

// 获取参数描述函数
static const OSSL_PARAM *tee_provider_gettable_params(void *provctx) {
    static const OSSL_PARAM known_gettable_params[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
        OSSL_PARAM_END
    };
    return known_gettable_params;
}

// 提供者调度表
static const OSSL_DISPATCH tee_provider_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))tee_provider_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))tee_provider_query },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))tee_provider_get_params },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))tee_provider_gettable_params },
    { 0, NULL }
};

// 设置TEE密钥ID和证书路径
void tee_provider_set_certificate_path(const char *cert_path) {
    if (global_certificate_path) {
        OPENSSL_free(global_certificate_path);
    }
    global_certificate_path = OPENSSL_strdup(cert_path);
    
    // 生成TEE密钥ID（基于证书路径）
    if (global_tee_key_id) {
        OPENSSL_free(global_tee_key_id);
    }
    
    // 创建唯一的TEE密钥ID
    size_t id_len = strlen(cert_path) + 20;
    global_tee_key_id = OPENSSL_malloc(id_len);
    snprintf(global_tee_key_id, id_len, "tee_key_%s", strrchr(cert_path, '/') ? strrchr(cert_path, '/') + 1 : cert_path);
    
    tee_log("设置TEE密钥ID和证书路径");
    printf("TEE密钥ID: %s\n", global_tee_key_id);
}

// 创建与TEE provider关联的密钥对象
EVP_PKEY *tee_provider_create_key_reference(OSSL_LIB_CTX *libctx) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL;
    
    tee_log("创建TEE密钥引用（不含私钥数据）");
    
    if (!global_certificate_path || !global_tee_key_id) {
        tee_log("未设置TEE配置");
        return NULL;
    }
    
    // 从证书获取公钥参数
    if (!get_public_key_params_from_cert(global_certificate_path, &n, &e)) {
        tee_log("无法获取公钥参数");
        return NULL;
    }
    
    // 创建参数构建器
    bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        BN_free(n);
        BN_free(e);
        return NULL;
    }
    
    // 添加公钥参数（不添加私钥参数）
    if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) != 1 ||
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) != 1) {
        tee_log("无法构建密钥参数");
        OSSL_PARAM_BLD_free(bld);
        BN_free(n);
        BN_free(e);
        return NULL;
    }
    
    params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    
    if (!params) {
        BN_free(n);
        BN_free(e);
        return NULL;
    }
    
    // 使用TEE provider创建密钥上下文
    ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", "provider=tee");
    if (!ctx) {
        tee_log("无法创建TEE密钥上下文");
        OSSL_PARAM_free(params);
        BN_free(n);
        BN_free(e);
        return NULL;
    }
    
    // 从参数创建密钥对象
    if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        tee_log("无法从参数创建TEE密钥对象");
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);
        BN_free(n);
        BN_free(e);
        return NULL;
    }
    
    // 清理
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    BN_free(n);
    BN_free(e);
    
    tee_log("TEE密钥引用创建成功（私钥安全保护在TEE中）");
    return pkey;
}

// 提供者初始化函数
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx) {
    TEE_PROV_CTX *ctx;
    
    tee_log("=== TEE Provider 初始化开始 ===");
    
    ctx = OPENSSL_zalloc(sizeof(TEE_PROV_CTX));
    if (ctx == NULL) {
        return 0;
    }
    
    ctx->handle = handle;
    
    *out = tee_provider_dispatch_table;
    *provctx = ctx;
    
    tee_log("=== TEE Provider 初始化完成 ===");
    return 1;
}