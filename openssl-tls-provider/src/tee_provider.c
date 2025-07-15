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
    EVP_PKEY *pkey;
    EVP_MD_CTX *mdctx;
    char *mdname;
} TEE_SIG_CTX;

// TEE key management context
typedef struct {
    TEE_PROV_CTX *provctx;
    EVP_PKEY *pkey;
    int key_loaded;
} TEE_KEY_CTX;

// 全局变量存储私钥路径
static char *global_private_key_path = NULL;

// 日志函数
static void tee_log(const char *msg) {
    fprintf(stderr, "[TEE Provider] %s\n", msg);
}

// 清理函数
static void tee_provider_teardown(void *provctx) {
    TEE_PROV_CTX *ctx = (TEE_PROV_CTX *)provctx;
    if (ctx) {
        OPENSSL_free(ctx);
    }
    if (global_private_key_path) {
        OPENSSL_free(global_private_key_path);
        global_private_key_path = NULL;
    }
}

// 签名操作的新建函数
static void *tee_signature_newctx(void *provctx, const char *propq) {
    TEE_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(TEE_SIG_CTX));
    if (ctx == NULL) {
        return NULL;
    }
    
    ctx->provctx = (TEE_PROV_CTX *)provctx;
    ctx->mdctx = EVP_MD_CTX_new();
    if (ctx->mdctx == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }
    
    tee_log("签名上下文创建成功");
    return ctx;
}

// 签名操作的释放函数
static void tee_signature_freectx(void *ctx) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    if (sigctx) {
        if (sigctx->mdctx) {
            EVP_MD_CTX_free(sigctx->mdctx);
        }
        if (sigctx->pkey) {
            EVP_PKEY_free(sigctx->pkey);
        }
        if (sigctx->mdname) {
            OPENSSL_free(sigctx->mdname);
        }
        OPENSSL_free(sigctx);
    }
}

// 从文件加载私钥（模拟TEE中的私钥加载）
static EVP_PKEY *load_private_key_from_tee(const char *key_path) {
    FILE *fp = fopen(key_path, "rb");
    if (!fp) {
        tee_log("无法打开私钥文件");
        return NULL;
    }
    
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!pkey) {
        tee_log("无法解析私钥");
        return NULL;
    }
    
    tee_log("私钥加载成功（模拟TEE环境）");
    return pkey;
}

// 签名初始化函数
static int tee_signature_digest_sign_init(void *ctx, const char *mdname, void *provkey, const OSSL_PARAM params[]) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    if (!sigctx) {
        return 0;
    }
    
    // 如果没有提供私钥，从TEE环境加载
    if (!provkey && global_private_key_path) {
        sigctx->pkey = load_private_key_from_tee(global_private_key_path);
        if (!sigctx->pkey) {
            return 0;
        }
    } else if (provkey) {
        sigctx->pkey = (EVP_PKEY *)provkey;
        EVP_PKEY_up_ref(sigctx->pkey);
    }
    
    if (!sigctx->pkey) {
        tee_log("签名初始化失败：无私钥");
        return 0;
    }
    
    // 设置消息摘要算法
    if (mdname) {
        sigctx->mdname = OPENSSL_strdup(mdname);
        const EVP_MD *md = EVP_get_digestbyname(mdname);
        if (!md) {
            tee_log("不支持的摘要算法");
            return 0;
        }
        
        if (EVP_DigestSignInit(sigctx->mdctx, NULL, md, NULL, sigctx->pkey) <= 0) {
            tee_log("签名初始化失败");
            return 0;
        }
    }
    
    tee_log("签名初始化成功");
    return 1;
}

// 签名更新函数
static int tee_signature_digest_sign_update(void *ctx, const unsigned char *data, size_t datalen) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    if (!sigctx || !sigctx->mdctx) {
        return 0;
    }
    
    if (EVP_DigestSignUpdate(sigctx->mdctx, data, datalen) <= 0) {
        tee_log("签名更新失败");
        return 0;
    }
    
    return 1;
}

// 签名最终函数
static int tee_signature_digest_sign_final(void *ctx, unsigned char *sig, size_t *siglen, size_t sigsize) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    if (!sigctx || !sigctx->mdctx) {
        return 0;
    }
    
    tee_log("执行TEE签名操作");
    
    if (EVP_DigestSignFinal(sigctx->mdctx, sig, siglen) <= 0) {
        tee_log("签名失败");
        return 0;
    }
    
    tee_log("TEE签名操作成功");
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

// ==================== 密钥管理操作 ====================

// 创建新的密钥管理上下文
static void *tee_keymgmt_new(void *provctx) {
    TEE_KEY_CTX *ctx = OPENSSL_zalloc(sizeof(TEE_KEY_CTX));
    if (ctx == NULL) {
        return NULL;
    }
    
    ctx->provctx = (TEE_PROV_CTX *)provctx;
    ctx->key_loaded = 0;
    
    tee_log("密钥管理上下文创建成功");
    return ctx;
}

// 释放密钥管理上下文
static void tee_keymgmt_free(void *keydata) {
    TEE_KEY_CTX *ctx = (TEE_KEY_CTX *)keydata;
    if (ctx) {
        if (ctx->pkey) {
            EVP_PKEY_free(ctx->pkey);
        }
        OPENSSL_free(ctx);
    }
}

// 从TEE环境加载私钥
static void *tee_keymgmt_load(const void *reference, size_t reference_sz) {
    TEE_KEY_CTX *ctx = OPENSSL_zalloc(sizeof(TEE_KEY_CTX));
    if (ctx == NULL) {
        return NULL;
    }
    
    tee_log("TEE密钥管理：开始加载私钥");
    
    // 在真实TEE中，这里会从安全存储加载私钥
    // 这里我们模拟从指定路径加载私钥
    if (global_private_key_path) {
        ctx->pkey = load_private_key_from_tee(global_private_key_path);
        if (ctx->pkey) {
            ctx->key_loaded = 1;
            tee_log("TEE密钥管理：私钥加载成功");
        } else {
            tee_log("TEE密钥管理：私钥加载失败");
            OPENSSL_free(ctx);
            return NULL;
        }
    }
    
    return ctx;
}

// 检查密钥是否存在
static int tee_keymgmt_has(const void *keydata, int selection) {
    const TEE_KEY_CTX *ctx = (const TEE_KEY_CTX *)keydata;
    if (ctx == NULL) {
        return 0;
    }
    
    // 检查是否有私钥
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        return ctx->key_loaded && ctx->pkey != NULL;
    }
    
    return 0;
}

// 匹配密钥
static int tee_keymgmt_match(const void *keydata1, const void *keydata2, int selection) {
    const TEE_KEY_CTX *ctx1 = (const TEE_KEY_CTX *)keydata1;
    const TEE_KEY_CTX *ctx2 = (const TEE_KEY_CTX *)keydata2;
    
    if (ctx1 == NULL || ctx2 == NULL) {
        return 0;
    }
    
    if (ctx1->pkey && ctx2->pkey) {
        return EVP_PKEY_eq(ctx1->pkey, ctx2->pkey);
    }
    
    return 0;
}

// 导出公钥
static int tee_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg) {
    TEE_KEY_CTX *ctx = (TEE_KEY_CTX *)keydata;
    
    if (ctx == NULL || ctx->pkey == NULL) {
        return 0;
    }
    
    // 对于TEE模式，我们只导出公钥部分
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        tee_log("TEE密钥管理：导出公钥");
        return 1;
    }
    
    return 0;
}

// 密钥管理操作调度表
static const OSSL_DISPATCH tee_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tee_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))tee_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))tee_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))tee_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))tee_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))tee_keymgmt_export },
    { 0, NULL }
};

// 算法查询函数
static const OSSL_ALGORITHM *tee_provider_query(void *provctx, int operation_id, int *no_cache) {
    *no_cache = 0;
    
    switch (operation_id) {
        case OSSL_OP_SIGNATURE:
            {
                static const OSSL_ALGORITHM signature_algs[] = {
                    { "RSA", "provider=tee", tee_signature_functions },
                    { "RSA-PSS", "provider=tee", tee_signature_functions },
                    { NULL, NULL, NULL }
                };
                return signature_algs;
            }
        case OSSL_OP_KEYMGMT:
            {
                static const OSSL_ALGORITHM keymgmt_algs[] = {
                    { "RSA", "provider=tee", tee_keymgmt_functions },
                    { "RSA-PSS", "provider=tee", tee_keymgmt_functions },
                    { NULL, NULL, NULL }
                };
                tee_log("TEE Provider：返回密钥管理算法");
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

// 设置私钥路径函数
void tee_provider_set_private_key_path(const char *path) {
    if (global_private_key_path) {
        OPENSSL_free(global_private_key_path);
    }
    global_private_key_path = OPENSSL_strdup(path);
}

// 提供者初始化函数
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, const OSSL_DISPATCH **out, void **provctx) {
    TEE_PROV_CTX *ctx;
    
    tee_log("TEE Provider 初始化开始");
    
    ctx = OPENSSL_zalloc(sizeof(TEE_PROV_CTX));
    if (ctx == NULL) {
        return 0;
    }
    
    ctx->handle = handle;
    
    *out = tee_provider_dispatch_table;
    *provctx = ctx;
    
    tee_log("TEE Provider 初始化完成");
    return 1;
}