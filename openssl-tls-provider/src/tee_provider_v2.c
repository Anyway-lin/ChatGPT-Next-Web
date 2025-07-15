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
#define TEE_PROVIDER_VERSION "2.0.0"

// TEE Provider context
typedef struct {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
} TEE_PROV_CTX;

// TEE Key context - 代表TEE中的密钥
typedef struct {
    TEE_PROV_CTX *provctx;
    char *tee_key_id;          // TEE密钥标识符
    BIGNUM *n, *e;             // 公钥参数（用于验证和协议兼容）
    int key_size;              // 密钥大小
    int key_valid;             // 密钥是否在TEE中有效
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

// 日志函数
static void tee_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "[TEE-V2] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

// TEE模拟接口 - 在真实环境中这些会调用TEE API
static int tee_interface_sign(const char *key_id, const unsigned char *digest, 
                             size_t digest_len, unsigned char *signature, 
                             size_t *sig_len) {
    tee_log("🔐 TEE接口：执行安全签名");
    tee_log("密钥ID: %s", key_id);
    tee_log("摘要长度: %zu 字节", digest_len);
    
    // 在真实TEE中，这里会：
    // 1. 验证key_id的有效性
    // 2. 在TEE安全环境中使用私钥签名
    // 3. 返回签名结果，私钥永不离开TEE
    
    // 模拟实现：临时加载私钥进行签名（仅用于演示）
    FILE *fp = fopen("./certs/client.key", "rb");
    if (!fp) {
        tee_log("❌ TEE接口：无法访问密钥存储");
        return 0;
    }
    
    EVP_PKEY *tee_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!tee_key) {
        tee_log("❌ TEE接口：密钥验证失败");
        return 0;
    }
    
    // 执行签名
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(tee_key, NULL);
    if (!ctx) {
        EVP_PKEY_free(tee_key);
        return 0;
    }
    
    if (EVP_PKEY_sign_init(ctx) <= 0 ||
        EVP_PKEY_sign(ctx, signature, sig_len, digest, digest_len) <= 0) {
        tee_log("❌ TEE接口：签名操作失败");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(tee_key);
        return 0;
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(tee_key);
    
    tee_log("✅ TEE接口：签名成功，长度 %zu 字节", *sig_len);
    return 1;
}

// 从证书获取公钥参数
static int extract_public_key_params(const char *cert_path, BIGNUM **n, BIGNUM **e, int *key_size) {
    FILE *fp = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pub_key = NULL;
    int ret = 0;
    
    tee_log("📋 从证书提取公钥参数: %s", cert_path);
    
    fp = fopen(cert_path, "rb");
    if (!fp) {
        tee_log("❌ 无法打开证书文件");
        return 0;
    }
    
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!cert) {
        tee_log("❌ 无法解析证书");
        return 0;
    }
    
    pub_key = X509_get_pubkey(cert);
    if (!pub_key) {
        tee_log("❌ 无法获取证书公钥");
        X509_free(cert);
        return 0;
    }
    
    if (EVP_PKEY_id(pub_key) != EVP_PKEY_RSA) {
        tee_log("❌ 证书不是RSA类型");
        EVP_PKEY_free(pub_key);
        X509_free(cert);
        return 0;
    }
    
    // 使用新的OpenSSL 3.x API
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
// TEE Key Management 实现
// ================================

static void *tee_keymgmt_new(void *provctx) {
    TEE_KEY_CTX *ctx = OPENSSL_zalloc(sizeof(TEE_KEY_CTX));
    if (ctx) {
        ctx->provctx = (TEE_PROV_CTX *)provctx;
        ctx->key_valid = 0;
        tee_log("🔑 密钥管理：创建新的TEE密钥上下文");
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
        OPENSSL_free(ctx);
    }
}

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
    
    // TEE模式：私钥在TEE中，公钥参数可用
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        tee_log("✅ 确认：TEE中有私钥");
        return 1;
    }
    
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        int has_pubkey = (ctx->n != NULL && ctx->e != NULL);
        tee_log("%s 公钥参数: %s", has_pubkey ? "✅" : "❌", 
                has_pubkey ? "可用" : "不可用");
        return has_pubkey;
    }
    
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
        // TEE模式：我们同时有私钥（在TEE中）和公钥参数
        int has_keypair = (ctx->n != NULL && ctx->e != NULL);
        tee_log("✅ TEE密钥对：私钥在TEE中，公钥参数%s", has_keypair ? "可用" : "不可用");
        return has_keypair;
    }
    
    tee_log("✅ 其他选择支持");
    return 1;
}

static int tee_keymgmt_match(const void *keydata1, const void *keydata2, int selection) {
    const TEE_KEY_CTX *ctx1 = (const TEE_KEY_CTX *)keydata1;
    const TEE_KEY_CTX *ctx2 = (const TEE_KEY_CTX *)keydata2;
    
    tee_log("🔑 密钥管理：匹配密钥 (selection=%d)", selection);
    
    if (!ctx1 || !ctx2) {
        tee_log("❌ 密钥上下文为空");
        return 0;
    }
    
    if (!ctx1->key_valid || !ctx2->key_valid) {
        tee_log("❌ 密钥无效");
        return 0;
    }
    
    // 通过TEE密钥ID匹配
    if (ctx1->tee_key_id && ctx2->tee_key_id) {
        int match = strcmp(ctx1->tee_key_id, ctx2->tee_key_id) == 0;
        tee_log("%s 密钥ID匹配: %s", match ? "✅" : "❌", 
                match ? "相同TEE密钥" : "不同TEE密钥");
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
    
    tee_log("⚠️  无法比较密钥");
    return 0;
}

// 关键函数：从参数创建TEE密钥
static void *tee_keymgmt_fromdata(void *provctx, const OSSL_PARAM params[]) {
    TEE_KEY_CTX *ctx = NULL;
    
    tee_log("🔑 密钥管理：从参数创建TEE密钥");
    
    // 检查是否有全局TEE密钥ID
    if (!global_tee_key_id) {
        tee_log("❌ 未配置TEE密钥ID");
        return NULL;
    }
    
    ctx = tee_keymgmt_new(provctx);
    if (!ctx) {
        tee_log("❌ 无法创建密钥上下文");
        return NULL;
    }
    
    // 简化实现：不处理复杂的参数，直接从全局配置获取公钥信息
    BIGNUM *n = NULL, *e = NULL;
    int key_size = 0;
    
    if (extract_public_key_params(global_cert_path, &n, &e, &key_size)) {
        ctx->n = n;
        ctx->e = e;
        ctx->key_size = key_size;
        tee_log("✅ 从全局配置获取公钥参数");
    } else {
        tee_log("⚠️  使用默认密钥大小");
        ctx->key_size = 2048;
    }
    
    // 设置TEE密钥ID和基本信息
    ctx->tee_key_id = OPENSSL_strdup(global_tee_key_id);
    if (!ctx->tee_key_id) {
        tee_log("❌ 无法复制TEE密钥ID");
        tee_keymgmt_free(ctx);
        return NULL;
    }
    
    ctx->key_valid = 1;
    
    tee_log("✅ TEE密钥创建成功");
    tee_log("   密钥ID: %s", ctx->tee_key_id);
    tee_log("   密钥大小: %d bits", ctx->key_size);
    tee_log("   公钥参数: N=%s, E=%s", ctx->n ? "有" : "无", ctx->e ? "有" : "无");
    
    return ctx;
}

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
    
    // 导出公钥参数（私钥永不离开TEE）
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && ctx->n && ctx->e) {
        if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, ctx->n) == 1 &&
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, ctx->e) == 1) {
            tee_log("✅ 导出公钥参数（私钥保护在TEE中）");
        } else {
            tee_log("⚠️  导出公钥参数时出现问题");
        }
    }
    
    // 导出密钥大小信息
    if (ctx->key_size > 0) {
        if (OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_BITS, ctx->key_size) != 1) {
            tee_log("⚠️  导出密钥大小信息时出现问题");
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

// 关键函数：获取可导入的参数类型
static const OSSL_PARAM *tee_keymgmt_import_types(int selection) {
    static const OSSL_PARAM import_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_END
    };
    
    tee_log("🔑 密钥管理：查询可导入参数类型 (selection=%d)", selection);
    
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return import_types;
    }
    
    return NULL;
}

// 关键函数：获取可导出的参数类型
static const OSSL_PARAM *tee_keymgmt_export_types(int selection) {
    static const OSSL_PARAM export_types[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_END
    };
    
    tee_log("🔑 密钥管理：查询可导出参数类型 (selection=%d)", selection);
    
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return export_types;
    }
    
    return NULL;
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

// 关键函数：签名初始化
static int tee_signature_digest_sign_init(void *ctx, const char *mdname, 
                                         void *provkey, const OSSL_PARAM params[]) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    TEE_KEY_CTX *key_ctx = (TEE_KEY_CTX *)provkey;
    
    tee_log("🚀 签名：TEE签名初始化");
    tee_log("   摘要算法: %s", mdname ? mdname : "默认");
    
    if (!sigctx) {
        tee_log("❌ 签名上下文无效");
        return 0;
    }
    
    if (!key_ctx || !key_ctx->key_valid) {
        tee_log("❌ TEE密钥上下文无效");
        return 0;
    }
    
    // 关联TEE密钥
    sigctx->tee_key = key_ctx;
    
    // 设置摘要算法
    if (mdname) {
        sigctx->digest_name = OPENSSL_strdup(mdname);
    }
    
    // 初始化摘要数据缓冲区
    sigctx->digest_data = NULL;
    sigctx->digest_len = 0;
    sigctx->sign_initialized = 1;
    
    tee_log("✅ TEE签名初始化成功");
    tee_log("   TEE密钥ID: %s", key_ctx->tee_key_id);
    tee_log("   密钥大小: %d bits", key_ctx->key_size);
    
    return 1;
}

// 关键函数：签名数据更新
static int tee_signature_digest_sign_update(void *ctx, const unsigned char *data, 
                                           size_t datalen) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    
    tee_log("📝 签名：更新签名数据 (%zu 字节)", datalen);
    
    if (!sigctx || !sigctx->sign_initialized) {
        tee_log("❌ 签名上下文未初始化");
        return 0;
    }
    
    // 累积摘要数据（简化实现）
    // 在真实实现中，这里会将数据发送到TEE进行摘要计算
    unsigned char *new_data = OPENSSL_realloc(sigctx->digest_data, 
                                             sigctx->digest_len + datalen);
    if (!new_data) {
        tee_log("❌ 内存分配失败");
        return 0;
    }
    
    sigctx->digest_data = new_data;
    memcpy(sigctx->digest_data + sigctx->digest_len, data, datalen);
    sigctx->digest_len += datalen;
    
    tee_log("✅ 累积数据更新，总长度: %zu 字节", sigctx->digest_len);
    return 1;
}

// 关键函数：签名完成 - 这是核心！
static int tee_signature_digest_sign_final(void *ctx, unsigned char *sig, 
                                          size_t *siglen, size_t sigsize) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    
    tee_log("🎯 签名：TEE签名最终操作（核心函数被调用！）");
    
    if (!sigctx || !sigctx->sign_initialized || !sigctx->tee_key) {
        tee_log("❌ 签名上下文或TEE密钥无效");
        return 0;
    }
    
    // 如果只是查询签名长度
    if (!sig) {
        *siglen = sigctx->tee_key->key_size / 8; // RSA签名长度 = 密钥长度
        tee_log("📏 返回签名长度: %zu 字节", *siglen);
        return 1;
    }
    
    // 执行实际的TEE签名
    tee_log("🔐 调用TEE接口进行安全签名");
    tee_log("   TEE密钥ID: %s", sigctx->tee_key->tee_key_id);
    tee_log("   摘要数据: %zu 字节", sigctx->digest_len);
    
    // 调用TEE签名接口
    if (!tee_interface_sign(sigctx->tee_key->tee_key_id, 
                           sigctx->digest_data, sigctx->digest_len,
                           sig, siglen)) {
        tee_log("❌ TEE签名失败");
        return 0;
    }
    
    tee_log("🎉 TEE签名成功完成！");
    tee_log("   签名长度: %zu 字节", *siglen);
    
    return 1;
}

// ================================
// Provider 调度表定义
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

// ================================
// Provider 主要接口
// ================================

static const OSSL_ALGORITHM *tee_provider_query(void *provctx, int operation_id, 
                                               int *no_cache) {
    *no_cache = 0;
    
    switch (operation_id) {
        case OSSL_OP_SIGNATURE:
            {
                static const OSSL_ALGORITHM signature_algs[] = {
                    { "RSA", "provider=tee,fips=no", tee_signature_functions, "TEE RSA signature" },
                    { NULL, NULL, NULL, NULL }
                };
                tee_log("🔍 查询：返回TEE签名算法");
                return signature_algs;
            }
        case OSSL_OP_KEYMGMT:
            {
                static const OSSL_ALGORITHM keymgmt_algs[] = {
                    { "RSA", "provider=tee,fips=no", tee_keymgmt_functions, "TEE RSA key management" },
                    { NULL, NULL, NULL, NULL }
                };
                tee_log("🔍 查询：返回TEE密钥管理算法");
                return keymgmt_algs;
            }
        default:
            return NULL;
    }
}

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

static const OSSL_PARAM *tee_provider_gettable_params(void *provctx) {
    static const OSSL_PARAM known_gettable_params[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
        OSSL_PARAM_END
    };
    return known_gettable_params;
}

static void tee_provider_teardown(void *provctx) {
    TEE_PROV_CTX *ctx = (TEE_PROV_CTX *)provctx;
    tee_log("🔄 TEE Provider 清理");
    if (ctx) {
        OPENSSL_free(ctx);
    }
    if (global_cert_path) {
        OPENSSL_free(global_cert_path);
        global_cert_path = NULL;
    }
    if (global_tee_key_id) {
        OPENSSL_free(global_tee_key_id);
        global_tee_key_id = NULL;
    }
}

static const OSSL_DISPATCH tee_provider_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))tee_provider_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))tee_provider_query },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))tee_provider_get_params },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))tee_provider_gettable_params },
    { 0, NULL }
};

// ================================
// 公共API接口
// ================================

// 配置TEE Provider
int tee_provider_configure(const char *cert_path) {
    BIGNUM *n = NULL, *e = NULL;
    int key_size = 0;
    
    tee_log("🔧 配置TEE Provider");
    tee_log("   证书路径: %s", cert_path);
    
    // 保存证书路径
    if (global_cert_path) {
        OPENSSL_free(global_cert_path);
    }
    global_cert_path = OPENSSL_strdup(cert_path);
    
    // 生成TEE密钥ID
    if (global_tee_key_id) {
        OPENSSL_free(global_tee_key_id);
    }
    
    const char *basename = strrchr(cert_path, '/');
    basename = basename ? basename + 1 : cert_path;
    
    size_t id_len = strlen(basename) + 20;
    global_tee_key_id = OPENSSL_malloc(id_len);
    snprintf(global_tee_key_id, id_len, "tee_key_%s", basename);
    
    // 验证证书并提取公钥参数
    if (!extract_public_key_params(cert_path, &n, &e, &key_size)) {
        tee_log("❌ 无法从证书提取公钥参数");
        return 0;
    }
    
    // 清理临时参数
    if (n) BN_free(n);
    if (e) BN_free(e);
    
    tee_log("✅ TEE Provider配置成功");
    tee_log("   TEE密钥ID: %s", global_tee_key_id);
    tee_log("   密钥大小: %d bits", key_size);
    
    return 1;
}

// 创建TEE密钥对象（不加载私钥文件）
EVP_PKEY *tee_provider_create_key(OSSL_LIB_CTX *libctx) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *n = NULL, *e = NULL;
    int key_size = 0;
    
    tee_log("🔑 创建TEE密钥对象（私钥保护在TEE中）");
    
    if (!global_cert_path || !global_tee_key_id) {
        tee_log("❌ TEE Provider未配置");
        return NULL;
    }
    
    // 从证书获取公钥参数
    if (!extract_public_key_params(global_cert_path, &n, &e, &key_size)) {
        tee_log("❌ 无法获取公钥参数");
        return NULL;
    }
    
    // 构建密钥参数
    bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        goto cleanup;
    }
    
    if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) != 1 ||
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) != 1 ||
        OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_BITS, key_size) != 1) {
        tee_log("❌ 无法构建密钥参数");
        goto cleanup;
    }
    
    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) {
        goto cleanup;
    }
    
    // 使用TEE provider创建密钥上下文
    ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", "provider=tee");
    if (!ctx) {
        tee_log("❌ 无法创建TEE密钥上下文");
        goto cleanup;
    }
    
    // 从参数导入密钥（这会调用我们的fromdata函数）
    if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        tee_log("❌ 无法从参数创建TEE密钥");
        goto cleanup;
    }
    
    tee_log("✅ TEE密钥对象创建成功");
    tee_log("   密钥已绑定到TEE Provider");
    tee_log("   私钥操作将调用TEE接口");
    
cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (params) OSSL_PARAM_free(params);
    if (bld) OSSL_PARAM_BLD_free(bld);
    if (n) BN_free(n);
    if (e) BN_free(e);
    
    return pkey;
}

// Provider初始化函数
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in, 
                      const OSSL_DISPATCH **out, void **provctx) {
    TEE_PROV_CTX *ctx;
    
    tee_log("🚀 TEE Provider V2 初始化开始");
    
    ctx = OPENSSL_zalloc(sizeof(TEE_PROV_CTX));
    if (ctx == NULL) {
        return 0;
    }
    
    ctx->handle = handle;
    
    *out = tee_provider_dispatch_table;
    *provctx = ctx;
    
    tee_log("✅ TEE Provider V2 初始化完成");
    return 1;
}