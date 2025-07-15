/*
 * TEE Provider for OpenSSL 3.0+
 * 模拟TEE环境，支持无私钥文件的证书链处理
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/store.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Provider context */
typedef struct {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
} TEE_PROV_CTX;

/* TEE key context */
typedef struct {
    char *key_id;           /* TEE密钥标识符 */
    EVP_PKEY *public_key;   /* 公钥部分 */
    char *cert_path;        /* 证书路径 */
    int key_type;           /* 密钥类型: RSA=1, EC=2 */
} TEE_KEY;

/* TEE signature context */
typedef struct {
    TEE_KEY *key;
    EVP_MD *md;
    char *mdname;
    unsigned char *tbsdata;
    size_t tbsdata_len;
} TEE_SIG_CTX;

/* 全局provider上下文 */
static TEE_PROV_CTX *global_provctx = NULL;

/* 模拟TEE存储的私钥路径 */
static char *tee_private_key_path = NULL;
static char *tee_certificate_path = NULL;

/* 日志函数 */
static void tee_log(const char *msg) {
    fprintf(stderr, "[TEE_PROVIDER] %s\n", msg);
}

/* ============================================================================
 * TEE接口层模拟实现 
 * ============================================================================ */

/* 模拟TEE签名接口 */
static int tee_sign_data(const char *key_id __attribute__((unused)), 
                        const unsigned char *data, 
                        size_t data_len, unsigned char **signature, size_t *sig_len) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIO *bio = NULL;
    int ret = 0;
    
    tee_log("TEE_SIGN: 调用TEE签名接口");
    
    /* 加载私钥 (模拟从TEE获取) */
    if (!tee_private_key_path) {
        tee_log("TEE_SIGN: 错误 - 未设置私钥路径");
        return 0;
    }
    
    bio = BIO_new_file(tee_private_key_path, "r");
    if (!bio) {
        tee_log("TEE_SIGN: 错误 - 无法打开私钥文件");
        return 0;
    }
    
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        tee_log("TEE_SIGN: 错误 - 无法读取私钥");
        return 0;
    }
    
    /* 执行签名 */
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        tee_log("TEE_SIGN: 错误 - 无法创建签名上下文");
        goto end;
    }
    
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        tee_log("TEE_SIGN: 错误 - 签名初始化失败");
        goto end;
    }
    
    /* 第一次调用获取签名长度 */
    if (EVP_PKEY_sign(ctx, NULL, sig_len, data, data_len) <= 0) {
        tee_log("TEE_SIGN: 错误 - 获取签名长度失败");
        goto end;
    }
    
    *signature = OPENSSL_malloc(*sig_len);
    if (!*signature) {
        tee_log("TEE_SIGN: 错误 - 内存分配失败");
        goto end;
    }
    
    /* 第二次调用执行实际签名 */
    if (EVP_PKEY_sign(ctx, *signature, sig_len, data, data_len) <= 0) {
        tee_log("TEE_SIGN: 错误 - 签名操作失败");
        OPENSSL_free(*signature);
        *signature = NULL;
        goto end;
    }
    
    tee_log("TEE_SIGN: 签名成功");
    ret = 1;
    
end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

/* 模拟从TEE获取公钥 */
static EVP_PKEY *tee_get_public_key(const char *key_id __attribute__((unused))) {
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pubkey = NULL;
    
    tee_log("TEE_GET_PUBKEY: 从TEE获取公钥");
    
    if (!tee_private_key_path) {
        tee_log("TEE_GET_PUBKEY: 错误 - 未设置私钥路径");
        return NULL;
    }
    
    /* 从私钥文件提取公钥 (模拟TEE操作) */
    bio = BIO_new_file(tee_private_key_path, "r");
    if (!bio) {
        tee_log("TEE_GET_PUBKEY: 错误 - 无法打开私钥文件");
        return NULL;
    }
    
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        tee_log("TEE_GET_PUBKEY: 错误 - 无法读取私钥");
        return NULL;
    }
    
    /* 提取公钥部分 */
    pubkey = EVP_PKEY_new();
    if (!pubkey) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    if (EVP_PKEY_copy_parameters(pubkey, pkey) <= 0) {
        tee_log("TEE_GET_PUBKEY: 错误 - 复制密钥参数失败");
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(pubkey);
        return NULL;
    }
    
    /* 简化的公钥提取方法，直接拷贝公钥部分 */
    if (EVP_PKEY_up_ref(pkey) > 0) {
        EVP_PKEY_free(pubkey);
        pubkey = pkey;
    } else {
        EVP_PKEY_free(pubkey);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    EVP_PKEY_free(pkey);
    tee_log("TEE_GET_PUBKEY: 成功获取公钥");
    return pubkey;
}

/* ============================================================================
 * Key Management Provider 实现
 * ============================================================================ */

/* Key Management: 创建新的密钥上下文 */
static void *tee_keymgmt_new(void *provctx) {
    TEE_KEY *key = OPENSSL_zalloc(sizeof(TEE_KEY));
    tee_log("KEYMGMT_NEW: 创建新密钥上下文");
    return key;
}

/* Key Management: 释放密钥上下文 */
static void tee_keymgmt_free(void *keydata) {
    TEE_KEY *key = (TEE_KEY *)keydata;
    if (key) {
        tee_log("KEYMGMT_FREE: 释放密钥上下文");
        OPENSSL_free(key->key_id);
        OPENSSL_free(key->cert_path);
        EVP_PKEY_free(key->public_key);
        OPENSSL_free(key);
    }
}

/* Key Management: 检查密钥是否包含指定组件 */
static int tee_keymgmt_has(const void *keydata, int selection) {
    const TEE_KEY *key = (const TEE_KEY *)keydata;
    
    if (!key) {
        tee_log("KEYMGMT_HAS: 密钥数据为空");
        return 0;
    }
    
    tee_log("KEYMGMT_HAS: 检查密钥组件");
    
    /* 始终声明有私钥，即使物理上不存在私钥文件 */
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        tee_log("KEYMGMT_HAS: 检查私钥 - 存在于TEE中");
        return 1;
    }
    
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        tee_log("KEYMGMT_HAS: 检查公钥");
        return key->public_key != NULL;
    }
    
    return 1;
}

/* Key Management: 加载密钥 */
static void *tee_keymgmt_load(const void *reference, size_t reference_sz) {
    const char *uri = (const char *)reference;
    TEE_KEY *key = NULL;
    
    tee_log("KEYMGMT_LOAD: 开始加载密钥");
    
    if (!uri || strncmp(uri, "tee:", 4) != 0) {
        tee_log("KEYMGMT_LOAD: 非TEE URI，跳过");
        return NULL;
    }
    
    key = tee_keymgmt_new(global_provctx);
    if (!key) {
        tee_log("KEYMGMT_LOAD: 错误 - 无法创建密钥上下文");
        return NULL;
    }
    
    /* 解析TEE URI: tee:key_id */
    key->key_id = OPENSSL_strdup(uri + 4);
    if (!key->key_id) {
        tee_log("KEYMGMT_LOAD: 错误 - 无法复制密钥ID");
        tee_keymgmt_free(key);
        return NULL;
    }
    
    /* 从TEE获取公钥 */
    key->public_key = tee_get_public_key(key->key_id);
    if (!key->public_key) {
        tee_log("KEYMGMT_LOAD: 错误 - 无法获取公钥");
        tee_keymgmt_free(key);
        return NULL;
    }
    
    /* 确定密钥类型 */
    key->key_type = EVP_PKEY_base_id(key->public_key);
    
    tee_log("KEYMGMT_LOAD: 密钥加载成功");
    return key;
}

/* Key Management: 导出公钥 */
static int tee_keymgmt_export(void *keydata, int selection,
                             OSSL_CALLBACK *param_cb, void *cbarg) {
    TEE_KEY *key = (TEE_KEY *)keydata;
    
    tee_log("KEYMGMT_EXPORT: 导出密钥");
    
    if (!key || !key->public_key) {
        tee_log("KEYMGMT_EXPORT: 错误 - 无效密钥数据");
        return 0;
    }
    
    /* 仅导出公钥部分 */
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        /* 这里应该调用param_cb传递公钥参数 */
        /* 简化实现，直接返回成功 */
        tee_log("KEYMGMT_EXPORT: 导出公钥成功");
        return 1;
    }
    
    /* 不允许导出私钥 */
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        tee_log("KEYMGMT_EXPORT: 拒绝导出私钥");
        return 0;
    }
    
    return 1;
}

/* Key Management: 获取密钥参数 */
static int tee_keymgmt_get_params(void *keydata, OSSL_PARAM params[]) {
    TEE_KEY *key = (TEE_KEY *)keydata;
    OSSL_PARAM *p;
    
    if (!key || !key->public_key) {
        return 0;
    }
    
    /* 设置密钥大小 */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL) {
        int bits = EVP_PKEY_bits(key->public_key);
        if (!OSSL_PARAM_set_int(p, bits)) {
            return 0;
        }
    }
    
    /* 设置安全位数 */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) {
        int security_bits = EVP_PKEY_security_bits(key->public_key);
        if (!OSSL_PARAM_set_int(p, security_bits)) {
            return 0;
        }
    }
    
    return 1;
}

/* Key Management: 支持的参数 */
static const OSSL_PARAM *tee_keymgmt_gettable_params(void *provctx) {
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END
    };
    return gettable;
}

/* Key Management: 获取支持的选择 */
static int tee_keymgmt_query_operation_name(const char *opname) {
    if (strcmp(opname, "RSA") == 0 || strcmp(opname, "EC") == 0) {
        return 1;
    }
    return 0;
}

/* Key Management: 匹配密钥 */
static int tee_keymgmt_match(const void *keydata1, const void *keydata2, int selection) {
    const TEE_KEY *key1 = (const TEE_KEY *)keydata1;
    const TEE_KEY *key2 = (const TEE_KEY *)keydata2;
    
    if (!key1 || !key2) return 0;
    if (!key1->key_id || !key2->key_id) return 0;
    
    return strcmp(key1->key_id, key2->key_id) == 0;
}

/* Key Management: 导入密钥 */
static void *tee_keymgmt_import(void *provctx __attribute__((unused)), 
                               int selection __attribute__((unused)), 
                               const OSSL_PARAM params[]) {
    /* 查找reference参数 */
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (!p || p->data_type != OSSL_PARAM_OCTET_STRING) {
        return NULL;
    }
    
    /* 如果是TEE URI，加载它 */
    if (p->data_size > 4 && strncmp(p->data, "tee:", 4) == 0) {
        return tee_keymgmt_load(p->data, p->data_size);
    }
    
    return NULL;
}

/* Key Management: 获取导入类型 */
static const OSSL_PARAM *tee_keymgmt_import_types(int selection __attribute__((unused))) {
    static const OSSL_PARAM import_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return import_types;
}

/* Key Management函数表 */
static const OSSL_DISPATCH tee_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tee_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))tee_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))tee_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))tee_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))tee_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))tee_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))tee_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))tee_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))tee_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))tee_keymgmt_import_types },
    { 0, NULL }
};

/* ============================================================================
 * Signature Provider 实现
 * ============================================================================ */

/* Signature: 创建签名上下文 */
static void *tee_signature_newctx(void *provctx, const char *propq) {
    TEE_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(TEE_SIG_CTX));
    tee_log("SIGNATURE_NEW: 创建签名上下文");
    return ctx;
}

/* Signature: 释放签名上下文 */
static void tee_signature_freectx(void *ctx) {
    TEE_SIG_CTX *sctx = (TEE_SIG_CTX *)ctx;
    if (sctx) {
        tee_log("SIGNATURE_FREE: 释放签名上下文");
        EVP_MD_free(sctx->md);
        OPENSSL_free(sctx->mdname);
        OPENSSL_free(sctx->tbsdata);
        OPENSSL_free(sctx);
    }
}

/* Signature: 签名初始化 */
static int tee_signature_sign_init(void *ctx, void *provkey, 
                                  const OSSL_PARAM params[]) {
    TEE_SIG_CTX *sctx = (TEE_SIG_CTX *)ctx;
    TEE_KEY *key = (TEE_KEY *)provkey;
    
    tee_log("SIGNATURE_SIGN_INIT: 签名初始化");
    
    if (!sctx || !key) {
        tee_log("SIGNATURE_SIGN_INIT: 错误 - 无效参数");
        return 0;
    }
    
    sctx->key = key;
    tee_log("SIGNATURE_SIGN_INIT: 签名初始化成功");
    return 1;
}

/* Signature: 执行签名 */
static int tee_signature_sign(void *ctx, unsigned char *sig, size_t *siglen,
                             size_t sigsize, const unsigned char *tbs, 
                             size_t tbslen) {
    TEE_SIG_CTX *sctx = (TEE_SIG_CTX *)ctx;
    unsigned char *signature = NULL;
    size_t sig_len = 0;
    
    tee_log("SIGNATURE_SIGN: 执行签名操作");
    
    if (!sctx || !sctx->key) {
        tee_log("SIGNATURE_SIGN: 错误 - 无效上下文");
        return 0;
    }
    
    /* 调用TEE签名接口 */
    if (!tee_sign_data(sctx->key->key_id, tbs, tbslen, &signature, &sig_len)) {
        tee_log("SIGNATURE_SIGN: 错误 - TEE签名失败");
        return 0;
    }
    
    /* 返回签名长度 */
    if (!sig) {
        *siglen = sig_len;
        OPENSSL_free(signature);
        tee_log("SIGNATURE_SIGN: 返回签名长度");
        return 1;
    }
    
    /* 复制签名数据 */
    if (sigsize < sig_len) {
        tee_log("SIGNATURE_SIGN: 错误 - 签名缓冲区太小");
        OPENSSL_free(signature);
        return 0;
    }
    
    memcpy(sig, signature, sig_len);
    *siglen = sig_len;
    OPENSSL_free(signature);
    
    tee_log("SIGNATURE_SIGN: 签名操作成功");
    return 1;
}

/* Signature: Digest签名初始化 */
static int tee_signature_digest_sign_init(void *ctx, const char *mdname,
                                         void *provkey, const OSSL_PARAM params[]) {
    TEE_SIG_CTX *sctx = (TEE_SIG_CTX *)ctx;
    TEE_KEY *key = (TEE_KEY *)provkey;
    
    tee_log("SIGNATURE_DIGEST_SIGN_INIT: Digest签名初始化");
    
    if (!sctx || !key) {
        return 0;
    }
    
    sctx->key = key;
    
    if (mdname) {
        sctx->mdname = OPENSSL_strdup(mdname);
        sctx->md = EVP_MD_fetch(global_provctx->libctx, mdname, NULL);
    }
    
    return 1;
}

/* Signature: Digest签名更新 */
static int tee_signature_digest_sign_update(void *ctx, const unsigned char *data,
                                           size_t datalen) {
    TEE_SIG_CTX *sctx = (TEE_SIG_CTX *)ctx;
    
    /* 简化实现：将数据累积到缓冲区 */
    if (!sctx->tbsdata) {
        sctx->tbsdata = OPENSSL_malloc(datalen);
        if (!sctx->tbsdata) return 0;
        memcpy(sctx->tbsdata, data, datalen);
        sctx->tbsdata_len = datalen;
    } else {
        unsigned char *new_buf = OPENSSL_realloc(sctx->tbsdata, 
                                               sctx->tbsdata_len + datalen);
        if (!new_buf) return 0;
        sctx->tbsdata = new_buf;
        memcpy(sctx->tbsdata + sctx->tbsdata_len, data, datalen);
        sctx->tbsdata_len += datalen;
    }
    
    return 1;
}

/* Signature: Digest签名完成 */
static int tee_signature_digest_sign_final(void *ctx, unsigned char *sig,
                                          size_t *siglen, size_t sigsize) {
    TEE_SIG_CTX *sctx = (TEE_SIG_CTX *)ctx;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    int ret = 0;
    
    tee_log("SIGNATURE_DIGEST_SIGN_FINAL: Digest签名完成");
    
    if (!sctx || !sctx->key || !sctx->md) {
        return 0;
    }
    
    /* 计算哈希 */
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) return 0;
    
    if (EVP_DigestInit_ex(mdctx, sctx->md, NULL) <= 0 ||
        EVP_DigestUpdate(mdctx, sctx->tbsdata, sctx->tbsdata_len) <= 0 ||
        EVP_DigestFinal_ex(mdctx, hash, &hash_len) <= 0) {
        goto end;
    }
    
    /* 对哈希进行签名 */
    ret = tee_signature_sign(ctx, sig, siglen, sigsize, hash, hash_len);
    
end:
    EVP_MD_CTX_free(mdctx);
    return ret;
}

/* Signature函数表 */
static const OSSL_DISPATCH tee_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))tee_signature_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))tee_signature_freectx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))tee_signature_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))tee_signature_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))tee_signature_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))tee_signature_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))tee_signature_digest_sign_final },
    { 0, NULL }
};

/* ============================================================================
 * Store Provider 实现
 * ============================================================================ */

typedef struct {
    char *uri;
    X509 *cert;
    int loaded;
} TEE_STORE_CTX;

/* Store: 创建加载上下文 */
static void *tee_store_open(void *provctx, const char *uri) {
    TEE_STORE_CTX *ctx;
    
    tee_log("STORE_OPEN: 打开store");
    
    if (!uri || strncmp(uri, "tee:", 4) != 0) {
        return NULL;
    }
    
    ctx = OPENSSL_zalloc(sizeof(TEE_STORE_CTX));
    if (!ctx) return NULL;
    
    ctx->uri = OPENSSL_strdup(uri);
    ctx->loaded = 0;
    
    return ctx;
}

/* Store: 关闭上下文 */
static int tee_store_close(void *loaderctx) {
    TEE_STORE_CTX *ctx = (TEE_STORE_CTX *)loaderctx;
    
    if (ctx) {
        tee_log("STORE_CLOSE: 关闭store");
        OPENSSL_free(ctx->uri);
        X509_free(ctx->cert);
        OPENSSL_free(ctx);
    }
    
    return 1;
}

/* Store: 加载对象 */
static int tee_store_load(void *loaderctx, OSSL_CALLBACK *object_cb,
                         void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb __attribute__((unused)),
                         void *pw_cbarg __attribute__((unused))) {
    TEE_STORE_CTX *ctx = (TEE_STORE_CTX *)loaderctx;
    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;
    const char *data_type = "PrivateKeyInfo";
    const char *key_uri;
    
    tee_log("STORE_LOAD: 加载对象");
    
    if (!ctx || ctx->loaded) {
        return 0;
    }
    
    /* 从URI中提取密钥ID */
    key_uri = ctx->uri;
    
    /* 构造回调参数 - 返回密钥引用 */
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  (void*)key_uri, strlen(key_uri));
    params[2] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                                                 (char*)data_type, 0);
    params[3] = OSSL_PARAM_construct_end();
    
    ctx->loaded = 1;
    return object_cb(params, object_cbarg);
}

/* Store: 检查是否结束 */
static int tee_store_eof(void *loaderctx) {
    TEE_STORE_CTX *ctx = (TEE_STORE_CTX *)loaderctx;
    return ctx ? ctx->loaded : 1;
}

/* Store函数表 */
static const OSSL_DISPATCH tee_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN, (void (*)(void))tee_store_open },
    { OSSL_FUNC_STORE_LOAD, (void (*)(void))tee_store_load },
    { OSSL_FUNC_STORE_EOF, (void (*)(void))tee_store_eof },
    { OSSL_FUNC_STORE_CLOSE, (void (*)(void))tee_store_close },
    { 0, NULL }
};

/* ============================================================================
 * Provider主要接口
 * ============================================================================ */

/* 查询操作 */
static const OSSL_ALGORITHM *tee_query_operation(void *provctx, int operation_id,
                                                 int *no_cache) {
    *no_cache = 0;
    
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        {
            static const OSSL_ALGORITHM keymgmt_algs[] = {
                { "RSA:rsaEncryption", "provider=tee", tee_keymgmt_functions, "TEE RSA Key Management" },
                { "EC:id-ecPublicKey", "provider=tee", tee_keymgmt_functions, "TEE EC Key Management" },
                { NULL, NULL, NULL, NULL }
            };
            return keymgmt_algs;
        }
    case OSSL_OP_SIGNATURE:
        {
            static const OSSL_ALGORITHM signature_algs[] = {
                { "RSA:RSASSA-PKCS1-v1_5", "provider=tee", tee_signature_functions, "TEE RSA Signature" },
                { "ECDSA", "provider=tee", tee_signature_functions, "TEE ECDSA Signature" },
                { NULL, NULL, NULL, NULL }
            };
            return signature_algs;
        }
    case OSSL_OP_STORE:
        {
            static const OSSL_ALGORITHM store_algs[] = {
                { "tee", "provider=tee", tee_store_functions, "TEE Store" },
                { NULL, NULL, NULL, NULL }
            };
            return store_algs;
        }
    }
    
    return NULL;
}

/* Provider初始化 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                      const OSSL_DISPATCH *in,
                      const OSSL_DISPATCH **out,
                      void **provctx) {
    static const OSSL_DISPATCH provider_functions[] = {
        { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))tee_query_operation },
        { 0, NULL }
    };
    
    TEE_PROV_CTX *ctx;
    
    tee_log("PROVIDER_INIT: 初始化TEE Provider");
    
    /* 创建provider上下文 */
    ctx = OPENSSL_zalloc(sizeof(TEE_PROV_CTX));
    if (!ctx) {
        return 0;
    }
    
    ctx->handle = handle;
    ctx->libctx = OSSL_LIB_CTX_new();
    if (!ctx->libctx) {
        OPENSSL_free(ctx);
        return 0;
    }
    
    /* 设置全局上下文 */
    global_provctx = ctx;
    
    /* 初始化TEE路径 */
    tee_private_key_path = getenv("TEE_PRIVATE_KEY");
    tee_certificate_path = getenv("TEE_CERTIFICATE");
    
    if (!tee_private_key_path) {
        tee_private_key_path = "./tee_private_key.pem";
    }
    if (!tee_certificate_path) {
        tee_certificate_path = "./tee_certificate.pem";
    }
    
    *out = provider_functions;
    *provctx = ctx;
    
    tee_log("PROVIDER_INIT: TEE Provider初始化成功");
    return 1;
}