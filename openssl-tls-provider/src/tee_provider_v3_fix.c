#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
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
#define TEE_PROVIDER_VERSION "3.0.0"

// TEE Provider context
typedef struct {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
} TEE_PROV_CTX;

// TEE Key context - 关键修复：包含更完整的密钥信息
typedef struct {
    TEE_PROV_CTX *provctx;
    char *tee_key_id;          // TEE密钥标识符
    BIGNUM *n, *e, *d;         // 公钥参数 + 虚拟私钥指示器
    int key_size;              // 密钥大小
    int key_valid;             // 密钥是否在TEE中有效
    int has_private_key;       // 明确标记有私钥（在TEE中）
} TEE_KEY_CTX;

// TEE Signature context
typedef struct {
    TEE_PROV_CTX *provctx;
    TEE_KEY_CTX *tee_key;      // 关联的TEE密钥
    char *digest_name;         // 摘要算法名称
    unsigned char *digest_data; // 累积的摘要数据
    size_t digest_len;         // 摘要数据长度
    int sign_initialized;      // 签名是否已初始化
} TEE_SIG_CTX;

// 全局TEE状态
static char *global_cert_path = NULL;
static char *global_tee_key_id = NULL;
static BIGNUM *global_n = NULL;
static BIGNUM *global_e = NULL;
static int global_key_size = 0;

// 日志函数
static void tee_log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("[TEE-V3] ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

// TEE接口：模拟TEE中的签名操作
static int tee_interface_sign(const char *tee_key_id, 
                             const unsigned char *digest, size_t digest_len,
                             unsigned char *sig, size_t *sig_len) {
    tee_log("🔐 TEE接口：执行签名操作");
    tee_log("   TEE密钥ID: %s", tee_key_id);
    tee_log("   摘要长度: %zu bytes", digest_len);
    
    // 模拟TEE签名（实际实现应该调用真正的TEE API）
    // 这里我们创建一个假的签名用于演示
    unsigned char dummy_sig[256] = {0x30, 0x31, 0x32, 0x33}; // 假签名
    size_t dummy_len = 256;
    
    if (*sig_len < dummy_len) {
        *sig_len = dummy_len;
        return 0;
    }
    
    memcpy(sig, dummy_sig, dummy_len);
    *sig_len = dummy_len;
    
    tee_log("✅ TEE签名完成，签名长度: %zu bytes", *sig_len);
    return 1;
}

// 从证书提取公钥参数
static int extract_public_key_params(const char *cert_path, BIGNUM **n, BIGNUM **e, int *key_size) {
    X509 *cert = NULL;
    EVP_PKEY *pub_key = NULL;
    FILE *cert_file = NULL;
    
    tee_log("📋 从证书提取公钥参数: %s", cert_path);
    
    cert_file = fopen(cert_path, "r");
    if (!cert_file) {
        tee_log("❌ 无法打开证书文件");
        return 0;
    }
    
    cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    
    if (!cert) {
        tee_log("❌ 无法解析证书");
        return 0;
    }
    
    pub_key = X509_get_pubkey(cert);
    if (!pub_key) {
        tee_log("❌ 无法从证书获取公钥");
        X509_free(cert);
        return 0;
    }
    
    // 提取RSA参数
    if (EVP_PKEY_get_bn_param(pub_key, OSSL_PKEY_PARAM_RSA_N, n) != 1 ||
        EVP_PKEY_get_bn_param(pub_key, OSSL_PKEY_PARAM_RSA_E, e) != 1) {
        tee_log("❌ 无法获取RSA参数");
        EVP_PKEY_free(pub_key);
        X509_free(cert);
        return 0;
    }
    
    *key_size = EVP_PKEY_bits(pub_key);
    
    EVP_PKEY_free(pub_key);
    X509_free(cert);
    
    tee_log("✅ 公钥参数提取成功，密钥大小: %d bits", *key_size);
    return 1;
}

// ================================
// 关键修复：TEE Key Management 实现
// ================================

static void *tee_keymgmt_new(void *provctx) {
    TEE_KEY_CTX *ctx = OPENSSL_zalloc(sizeof(TEE_KEY_CTX));
    if (!ctx) {
        tee_log("❌ 无法分配TEE密钥上下文内存");
        return NULL;
    }
    
    ctx->provctx = (TEE_PROV_CTX *)provctx;
    ctx->key_valid = 0;
    ctx->has_private_key = 0;
    
    // 如果已经配置了全局TEE密钥，则自动加载
    if (global_cert_path && global_tee_key_id && global_n && global_e) {
        ctx->n = BN_dup(global_n);
        ctx->e = BN_dup(global_e);
        
        // 关键修复：创建虚拟私钥指示器
        ctx->d = BN_new();
        if (ctx->d) {
            BN_set_word(ctx->d, 1); // 设置为1表示"私钥存在但在TEE中"
        }
        
        ctx->key_size = global_key_size;
        ctx->tee_key_id = OPENSSL_strdup(global_tee_key_id);
        ctx->key_valid = 1;
        ctx->has_private_key = 1; // 明确标记有私钥
        
        tee_log("🔑 密钥管理：创建TEE密钥上下文（自动加载，包含虚拟私钥指示器）");
    } else {
        tee_log("🔑 密钥管理：创建空的TEE密钥上下文");
    }
    
    return ctx;
}

static void tee_keymgmt_free(void *keydata) {
    TEE_KEY_CTX *ctx = (TEE_KEY_CTX *)keydata;
    if (ctx) {
        tee_log("🔑 密钥管理：释放TEE密钥上下文");
        if (ctx->tee_key_id) OPENSSL_free(ctx->tee_key_id);
        if (ctx->n) BN_free(ctx->n);
        if (ctx->e) BN_free(ctx->e);
        if (ctx->d) BN_free(ctx->d); // 释放虚拟私钥指示器
        OPENSSL_free(ctx);
    }
}

// 关键修复：密钥能力检查
static int tee_keymgmt_has(const void *keydata, int selection) {
    const TEE_KEY_CTX *ctx = (const TEE_KEY_CTX *)keydata;
    
    tee_log("🔑 密钥管理：检查密钥能力 (selection=%d)", selection);
    
    if (!ctx) {
        tee_log("❌ 密钥上下文为空");
        return 0;
    }
    
    if (!ctx->key_valid) {
        tee_log("❌ TEE密钥无效");
        return 0;
    }
    
    // 检查私钥能力 - 关键修复
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        int has_private = ctx->has_private_key && ctx->d != NULL;
        tee_log("✅ 私钥检查：%s (TEE中保护)", has_private ? "有私钥" : "无私钥");
        return has_private;
    }
    
    // 检查公钥能力
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        int has_pubkey = (ctx->n != NULL && ctx->e != NULL);
        tee_log("✅ 公钥检查：%s", has_pubkey ? "有公钥参数" : "无公钥参数");
        return has_pubkey;
    }
    
    // 检查密钥对能力
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
        int has_keypair = (ctx->n != NULL && ctx->e != NULL && ctx->d != NULL && ctx->has_private_key);
        tee_log("✅ 密钥对检查：%s", has_keypair ? "完整密钥对" : "不完整");
        return has_keypair;
    }
    
    // 处理组合选择
    if ((selection & (OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) != 0) {
        int has_all = (ctx->n != NULL && ctx->e != NULL && ctx->d != NULL && ctx->has_private_key);
        tee_log("✅ 组合检查：%s", has_all ? "满足所有要求" : "不满足");
        return has_all;
    }
    
    tee_log("✅ 其他选择支持");
    return 1;
}

// 关键修复：密钥匹配
static int tee_keymgmt_match(const void *keydata1, const void *keydata2, int selection) {
    const TEE_KEY_CTX *ctx1 = (const TEE_KEY_CTX *)keydata1;
    const TEE_KEY_CTX *ctx2 = (const TEE_KEY_CTX *)keydata2;
    
    tee_log("🔑 密钥管理：匹配密钥 (selection=%d)", selection);
    
    if (!ctx1 || !ctx2) {
        tee_log("❌ 密钥上下文为空");
        return 0;
    }
    
    // 宽松的有效性检查
    int ctx1_valid = ctx1->key_valid;
    int ctx2_valid = ctx2->key_valid;
    
    tee_log("🔍 密钥有效性检查: ctx1=%s, ctx2=%s", 
            ctx1_valid ? "有效" : "无效", 
            ctx2_valid ? "有效" : "无效");
    
    if (!ctx1_valid && !ctx2_valid) {
        tee_log("❌ 两个密钥都无效");
        return 0;
    }
    
    // 找到有效的TEE密钥
    const TEE_KEY_CTX *tee_key = ctx1_valid ? ctx1 : ctx2;
    const TEE_KEY_CTX *other_key = ctx1_valid ? ctx2 : ctx1;
    
    // 通过TEE密钥ID匹配
    if (tee_key->tee_key_id && other_key->tee_key_id) {
        int match = strcmp(tee_key->tee_key_id, other_key->tee_key_id) == 0;
        tee_log("%s TEE密钥ID匹配: %s", match ? "✅" : "❌", 
                match ? "相同" : "不同");
        if (match) return 1;
    }
    
    // 通过公钥参数匹配
    if (ctx1->n && ctx2->n && ctx1->e && ctx2->e) {
        int n_match = (BN_cmp(ctx1->n, ctx2->n) == 0);
        int e_match = (BN_cmp(ctx1->e, ctx2->e) == 0);
        int match = n_match && e_match;
        tee_log("%s 公钥参数匹配: N=%s, E=%s", match ? "✅" : "❌",
                n_match ? "匹配" : "不匹配", e_match ? "匹配" : "不匹配");
        return match;
    }
    
    // 如果有TEE密钥ID，认为匹配成功
    if (tee_key->tee_key_id && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)) {
        tee_log("✅ TEE密钥匹配成功（基于TEE密钥ID）");
        return 1;
    }
    
    tee_log("⚠️  无法比较密钥");
    return 0;
}

// 从参数创建TEE密钥
static void *tee_keymgmt_fromdata(void *provctx, const OSSL_PARAM params[]) {
    tee_log("🔑 密钥管理：从参数创建TEE密钥");
    
    // 简化实现：直接使用全局配置创建密钥
    return tee_keymgmt_new(provctx);
}

// 关键修复：密钥导出
static int tee_keymgmt_export(void *keydata, int selection, 
                             OSSL_CALLBACK *param_cb, void *cbarg) {
    TEE_KEY_CTX *ctx = (TEE_KEY_CTX *)keydata;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    int ret = 0;
    
    tee_log("🔑 密钥管理：导出密钥参数 (selection=%d)", selection);
    
    if (!ctx || !ctx->key_valid) {
        tee_log("❌ 无效的TEE密钥上下文");
        return 0;
    }
    
    bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        return 0;
    }
    
    // 总是导出公钥参数
    if (ctx->n && ctx->e) {
        if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, ctx->n) == 1 &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, ctx->e) == 1) {
            tee_log("✅ 导出公钥参数 (N, E)");
        }
    }
    
    // 关键修复：当请求私钥时，导出虚拟私钥指示器
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && ctx->d && ctx->has_private_key) {
        if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, ctx->d) == 1) {
            tee_log("✅ 导出虚拟私钥指示器（实际私钥在TEE中安全保护）");
        }
    }
    
    // 导出密钥大小
    if (ctx->key_size > 0) {
        if (OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_BITS, ctx->key_size) == 1) {
            tee_log("✅ 导出密钥大小: %d bits", ctx->key_size);
        }
    }
    
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params) {
        ret = param_cb(params, cbarg);
        OSSL_PARAM_free(params);
        tee_log("✅ 密钥参数导出完成，返回值: %d", ret);
    }
    
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

// 获取可导入的参数类型
static const OSSL_PARAM *tee_keymgmt_import_types(int selection) {
    static const OSSL_PARAM import_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_END
    };
    
    tee_log("🔑 密钥管理：查询可导入参数类型 (selection=%d)", selection);
    return import_types;
}

// 关键修复：获取可导出的参数类型
static const OSSL_PARAM *tee_keymgmt_export_types(int selection) {
    static const OSSL_PARAM export_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),     // 公钥N
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),     // 公钥E
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),     // 私钥D（虚拟）
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),         // 密钥大小
        OSSL_PARAM_END
    };
    
    tee_log("🔑 密钥管理：查询可导出参数类型 (selection=%d)", selection);
    
    // 声明支持所有类型，包括私钥
    tee_log("✅ 声明支持完整的密钥参数类型（包括虚拟私钥）");
    return export_types;
}

// ================================
// TEE Signature 实现
// ================================

static void *tee_signature_newctx(void *provctx, const char *propq) {
    TEE_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(TEE_SIG_CTX));
    if (ctx) {
        ctx->provctx = (TEE_PROV_CTX *)provctx;
        ctx->sign_initialized = 0;
        tee_log("✅ 签名：创建TEE签名上下文");
    }
    return ctx;
}

static void tee_signature_freectx(void *ctx) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    if (sigctx) {
        tee_log("🔄 签名：释放TEE签名上下文");
        if (sigctx->digest_name) OPENSSL_free(sigctx->digest_name);
        if (sigctx->digest_data) OPENSSL_free(sigctx->digest_data);
        OPENSSL_free(sigctx);
    }
}

static int tee_signature_digest_sign_init(void *ctx, const char *mdname, 
                                         void *provkey, const OSSL_PARAM params[]) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    TEE_KEY_CTX *key_ctx = (TEE_KEY_CTX *)provkey;
    
    tee_log("🚀 签名：TEE签名初始化开始");
    tee_log("   摘要算法: %s", mdname ? mdname : "默认");
    
    if (!sigctx) {
        tee_log("❌ 签名上下文无效");
        return 0;
    }
    
    if (!key_ctx || !key_ctx->key_valid || !key_ctx->has_private_key) {
        tee_log("❌ TEE密钥上下文无效或无私钥");
        return 0;
    }
    
    // 关联TEE密钥
    sigctx->tee_key = key_ctx;
    
    // 保存摘要算法名称
    if (mdname) {
        sigctx->digest_name = OPENSSL_strdup(mdname);
    }
    
    sigctx->sign_initialized = 1;
    
    tee_log("✅ TEE签名初始化完成");
    tee_log("   关联TEE密钥ID: %s", key_ctx->tee_key_id);
    return 1;
}

static int tee_signature_digest_sign_update(void *ctx, const unsigned char *data, size_t datalen) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    
    tee_log("📝 签名：更新摘要数据，长度: %zu bytes", datalen);
    
    if (!sigctx || !sigctx->sign_initialized) {
        tee_log("❌ 签名上下文未初始化");
        return 0;
    }
    
    // 累积摘要数据（简化实现）
    if (!sigctx->digest_data) {
        sigctx->digest_data = OPENSSL_malloc(datalen);
        if (!sigctx->digest_data) {
            return 0;
        }
        memcpy(sigctx->digest_data, data, datalen);
        sigctx->digest_len = datalen;
    } else {
        // 扩展数据缓冲区
        unsigned char *new_data = OPENSSL_realloc(sigctx->digest_data, sigctx->digest_len + datalen);
        if (!new_data) {
            return 0;
        }
        sigctx->digest_data = new_data;
        memcpy(sigctx->digest_data + sigctx->digest_len, data, datalen);
        sigctx->digest_len += datalen;
    }
    
    tee_log("✅ 摘要数据更新完成，总长度: %zu bytes", sigctx->digest_len);
    return 1;
}

static int tee_signature_digest_sign_final(void *ctx, unsigned char *sig, 
                                          size_t *siglen, size_t sigsize) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    
    tee_log("🏁 签名：完成TEE签名操作");
    
    if (!sigctx || !sigctx->sign_initialized || !sigctx->tee_key) {
        tee_log("❌ 签名上下文或TEE密钥无效");
        return 0;
    }
    
    if (!sigctx->digest_data || sigctx->digest_len == 0) {
        tee_log("❌ 没有摘要数据需要签名");
        return 0;
    }
    
    // 调用TEE接口执行签名
    tee_log("🔐 调用TEE接口执行签名...");
    int result = tee_interface_sign(sigctx->tee_key->tee_key_id,
                                   sigctx->digest_data, sigctx->digest_len,
                                   sig, siglen);
    
    if (result) {
        tee_log("✅ TEE签名成功完成，签名长度: %zu bytes", *siglen);
    } else {
        tee_log("❌ TEE签名失败");
    }
    
    return result;
}

// ================================
// Provider 核心函数
// ================================

static const OSSL_DISPATCH tee_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tee_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))tee_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))tee_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))tee_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))tee_keymgmt_fromdata },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))tee_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))tee_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))tee_keymgmt_export_types },
    { 0, NULL }
};

static const OSSL_DISPATCH tee_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))tee_signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))tee_signature_freectx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))tee_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))tee_signature_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))tee_signature_digest_sign_final },
    { 0, NULL }
};

static const OSSL_ALGORITHM tee_signatures[] = {
    { "RSA:rsaEncryption", "provider=tee", tee_signature_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM tee_keymgmts[] = {
    { "RSA:rsaEncryption", "provider=tee", tee_keymgmt_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *tee_provider_query(void *provctx, int operation_id, int *no_cache) {
    *no_cache = 0;
    
    tee_log("🔍 查询：operation_id=%d", operation_id);
    
    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        tee_log("✅ 查询：返回TEE签名算法");
        return tee_signatures;
    case OSSL_OP_KEYMGMT:
        tee_log("✅ 查询：返回TEE密钥管理算法");
        return tee_keymgmts;
    default:
        tee_log("⚠️  查询：不支持的操作类型");
        return NULL;
    }
}

static int tee_provider_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;
    
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TEE_PROVIDER_NAME))
        return 0;
        
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, TEE_PROVIDER_VERSION))
        return 0;
        
    return 1;
}

static const OSSL_PARAM *tee_provider_gettable_params(void *provctx) {
    static const OSSL_PARAM param_types[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_END
    };
    return param_types;
}

static const OSSL_DISPATCH tee_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))tee_provider_query },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))tee_provider_get_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS_TABLE, (void (*)(void))tee_provider_gettable_params },
    { 0, NULL }
};

// ================================
// 公共API函数
// ================================

// 配置TEE Provider
int tee_provider_configure(const char *cert_path) {
    tee_log("🔧 配置TEE Provider");
    tee_log("   证书路径: %s", cert_path);
    
    // 清理之前的配置
    if (global_cert_path) {
        OPENSSL_free(global_cert_path);
        global_cert_path = NULL;
    }
    if (global_tee_key_id) {
        OPENSSL_free(global_tee_key_id);
        global_tee_key_id = NULL;
    }
    if (global_n) {
        BN_free(global_n);
        global_n = NULL;
    }
    if (global_e) {
        BN_free(global_e);
        global_e = NULL;
    }
    
    // 提取公钥参数
    BIGNUM *n = NULL, *e = NULL;
    int key_size = 0;
    
    if (!extract_public_key_params(cert_path, &n, &e, &key_size)) {
        tee_log("❌ 无法从证书提取公钥参数");
        return 0;
    }
    
    // 保存全局配置
    global_cert_path = OPENSSL_strdup(cert_path);
    global_tee_key_id = OPENSSL_strdup("tee_key_client.pem");
    global_n = n;
    global_e = e;
    global_key_size = key_size;
    
    tee_log("✅ TEE Provider配置成功");
    tee_log("   TEE密钥ID: %s", global_tee_key_id);
    tee_log("   密钥大小: %d bits", global_key_size);
    
    return 1;
}

// 创建TEE密钥对象
EVP_PKEY *tee_provider_create_key(OSSL_LIB_CTX *libctx) {
    tee_log("🔑 创建TEE密钥对象（私钥保护在TEE中）");
    
    if (!global_cert_path || !global_tee_key_id) {
        tee_log("❌ TEE Provider未配置");
        return NULL;
    }
    
    // 创建EVP_PKEY对象
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", "provider=tee");
    if (!ctx) {
        tee_log("❌ 无法创建EVP_PKEY_CTX");
        return NULL;
    }
    
    // 初始化密钥生成上下文  
    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        tee_log("❌ 无法初始化fromdata");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    // 构建密钥参数
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    // 添加公钥参数
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, global_n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, global_e);
    
    // 关键修复：添加虚拟私钥指示器
    BIGNUM *dummy_d = BN_new();
    BN_set_word(dummy_d, 1);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, dummy_d);
    
    OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_BITS, global_key_size);
    
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    
    // 创建密钥对象
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        tee_log("❌ 无法从参数创建密钥");
        BN_free(dummy_d);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    BN_free(dummy_d);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    
    tee_log("✅ TEE密钥对象创建成功");
    tee_log("   密钥已绑定到TEE Provider");
    tee_log("   私钥操作将调用TEE接口");
    
    return pkey;
}

// Provider清理
static void tee_provider_cleanup(void) {
    tee_log("🔄 TEE Provider 清理");
    
    if (global_cert_path) {
        OPENSSL_free(global_cert_path);
        global_cert_path = NULL;
    }
    if (global_tee_key_id) {
        OPENSSL_free(global_tee_key_id);
        global_tee_key_id = NULL;
    }
    if (global_n) {
        BN_free(global_n);
        global_n = NULL;
    }
    if (global_e) {
        BN_free(global_e);
        global_e = NULL;
    }
}

// Provider初始化函数
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out, void **provctx) {
    
    tee_log("🚀 TEE Provider V3 初始化开始");
    
    TEE_PROV_CTX *ctx = OPENSSL_zalloc(sizeof(TEE_PROV_CTX));
    if (!ctx) {
        return 0;
    }
    
    ctx->handle = handle;
    
    *provctx = ctx;
    *out = tee_dispatch_table;
    
    // 注册清理函数
    atexit(tee_provider_cleanup);
    
    tee_log("✅ TEE Provider V3 初始化完成");
    
    return 1;
}