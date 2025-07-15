#include "tee_provider.h"
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <string.h>

// TEE接口全局变量
const TEE_Interface *g_tee_interface = NULL;

// TEE密钥数据结构
typedef struct {
    uint32_t key_id;
    TEE_KeyType key_type;
    size_t key_bits;
    int has_private;
    int has_public;
} TEE_KEY;

// TEE签名上下文结构
typedef struct {
    TEE_PROV_CTX *provctx;
    TEE_KEY *key;
    TEE_Algorithm alg;
    int operation;  // 0=none, 1=sign, 2=verify
} TEE_SIG_CTX;

// ========================== 密钥管理实现 ==========================

void *tee_keymgmt_new(void *provctx) {
    TEE_KEY *key = calloc(1, sizeof(TEE_KEY));
    if (key == NULL) {
        return NULL;
    }
    key->key_id = 0;
    key->key_type = TEE_KEY_TYPE_RSA_2048;
    key->key_bits = 0;
    key->has_private = 0;
    key->has_public = 0;
    return key;
}

void tee_keymgmt_free(void *keydata) {
    TEE_KEY *key = (TEE_KEY *)keydata;
    if (key) {
        if (key->key_id && g_tee_interface && g_tee_interface->delete_key) {
            g_tee_interface->delete_key(key->key_id);
        }
        free(key);
    }
}

int tee_keymgmt_has(const void *keydata, int selection) {
    const TEE_KEY *key = (const TEE_KEY *)keydata;
    int ok = 0;

    if (key == NULL) {
        return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && key->has_private) {
        ok = 1;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) && key->has_public) {
        ok = 1;
    }

    return ok;
}

int tee_keymgmt_match(const void *keydata1, const void *keydata2, int selection) {
    const TEE_KEY *key1 = (const TEE_KEY *)keydata1;
    const TEE_KEY *key2 = (const TEE_KEY *)keydata2;

    if (key1 == NULL || key2 == NULL) {
        return 0;
    }

    return (key1->key_id == key2->key_id);
}

int tee_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[]) {
    TEE_KEY *key = (TEE_KEY *)keydata;
    const OSSL_PARAM *p;

    if (key == NULL) {
        return 0;
    }

    // 尝试导入密钥数据
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_TEE_KEY_ID);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &key->key_id)) {
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &key->key_bits)) {
            return 0;
        }
    }

    // 根据密钥长度确定密钥类型
    if (key->key_bits == 2048) {
        key->key_type = TEE_KEY_TYPE_RSA_2048;
    } else if (key->key_bits == 3072) {
        key->key_type = TEE_KEY_TYPE_RSA_3072;
    } else if (key->key_bits == 4096) {
        key->key_type = TEE_KEY_TYPE_RSA_4096;
    } else if (key->key_bits == 256) {
        key->key_type = TEE_KEY_TYPE_ECC_P256;
    } else if (key->key_bits == 384) {
        key->key_type = TEE_KEY_TYPE_ECC_P384;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        key->has_private = 1;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        key->has_public = 1;
    }

    return 1;
}

int tee_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *param_cb, void *cbarg) {
    TEE_KEY *key = (TEE_KEY *)keydata;
    OSSL_PARAM params[10];
    int idx = 0;

    if (key == NULL) {
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (key->key_id && g_tee_interface && g_tee_interface->export_public_key) {
            uint8_t pub_key[512];
            size_t pub_key_len = sizeof(pub_key);
            
            if (g_tee_interface->export_public_key(key->key_id, pub_key, &pub_key_len) == 0) {
                params[idx++] = OSSL_PARAM_construct_octet_string(
                    OSSL_PKEY_PARAM_PUB_KEY, pub_key, pub_key_len);
            }
        }
    }

    params[idx++] = OSSL_PARAM_construct_uint32(OSSL_PKEY_PARAM_TEE_KEY_ID, &key->key_id);
    params[idx++] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_BITS, &key->key_bits);
    params[idx++] = OSSL_PARAM_construct_end();

    return param_cb(params, cbarg);
}

const OSSL_PARAM *tee_keymgmt_import_types(int selection) {
    static const OSSL_PARAM import_types[] = {
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_TEE_KEY_ID, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return import_types;
}

const OSSL_PARAM *tee_keymgmt_export_types(int selection) {
    static const OSSL_PARAM export_types[] = {
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_TEE_KEY_ID, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    return export_types;
}

// ========================== 签名算法实现 ==========================

void *tee_signature_newctx(void *provctx, const char *propq) {
    TEE_SIG_CTX *ctx = calloc(1, sizeof(TEE_SIG_CTX));
    if (ctx == NULL) {
        return NULL;
    }
    
    ctx->provctx = (TEE_PROV_CTX *)provctx;
    ctx->key = NULL;
    ctx->alg = TEE_ALG_RSA_PKCS1_V1_5;
    ctx->operation = 0;
    
    return ctx;
}

int tee_signature_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[]) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    TEE_KEY *key = (TEE_KEY *)provkey;

    if (sigctx == NULL || key == NULL) {
        return 0;
    }

    if (!key->has_private) {
        tee_provider_set_error(TEE_ERR_KEY_NOT_FOUND, "Private key not available");
        return 0;
    }

    sigctx->key = key;
    sigctx->operation = 1; // sign operation
    
    // 根据密钥类型选择算法
    if (key->key_type == TEE_KEY_TYPE_RSA_2048 || 
        key->key_type == TEE_KEY_TYPE_RSA_3072 || 
        key->key_type == TEE_KEY_TYPE_RSA_4096) {
        sigctx->alg = TEE_ALG_RSA_PKCS1_V1_5;
    } else if (key->key_type == TEE_KEY_TYPE_ECC_P256) {
        sigctx->alg = TEE_ALG_ECDSA_P256;
    } else if (key->key_type == TEE_KEY_TYPE_ECC_P384) {
        sigctx->alg = TEE_ALG_ECDSA_P384;
    }

    return 1;
}

int tee_signature_sign(void *ctx, unsigned char *sig, size_t *siglen,
                       size_t sigsize, const unsigned char *tbs, size_t tbslen) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;

    if (sigctx == NULL || sigctx->key == NULL) {
        return 0;
    }

    if (sigctx->operation != 1) {
        tee_provider_set_error(TEE_ERR_INVALID_PARAMETER, "Not in sign mode");
        return 0;
    }

    if (!g_tee_interface || !g_tee_interface->sign) {
        tee_provider_set_error(TEE_ERR_TEE_OPERATION, "TEE interface not available");
        return 0;
    }

    // 如果只是查询签名长度
    if (sig == NULL) {
        if (sigctx->key->key_type == TEE_KEY_TYPE_RSA_2048) {
            *siglen = 256;
        } else if (sigctx->key->key_type == TEE_KEY_TYPE_RSA_3072) {
            *siglen = 384;
        } else if (sigctx->key->key_type == TEE_KEY_TYPE_RSA_4096) {
            *siglen = 512;
        } else if (sigctx->key->key_type == TEE_KEY_TYPE_ECC_P256) {
            *siglen = 72; // DER编码的ECDSA签名最大长度
        } else if (sigctx->key->key_type == TEE_KEY_TYPE_ECC_P384) {
            *siglen = 104;
        }
        return 1;
    }

    // 执行签名
    size_t actual_siglen = sigsize;
    int ret = g_tee_interface->sign(sigctx->key->key_id, sigctx->alg,
                                    tbs, tbslen, sig, &actual_siglen);
    
    if (ret == 0) {
        *siglen = actual_siglen;
        return 1;
    } else {
        tee_provider_set_error(TEE_ERR_TEE_OPERATION, "TEE signature operation failed");
        return 0;
    }
}

int tee_signature_verify_init(void *ctx, void *provkey, const OSSL_PARAM params[]) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    TEE_KEY *key = (TEE_KEY *)provkey;

    if (sigctx == NULL || key == NULL) {
        return 0;
    }

    sigctx->key = key;
    sigctx->operation = 2; // verify operation
    
    // 根据密钥类型选择算法
    if (key->key_type == TEE_KEY_TYPE_RSA_2048 || 
        key->key_type == TEE_KEY_TYPE_RSA_3072 || 
        key->key_type == TEE_KEY_TYPE_RSA_4096) {
        sigctx->alg = TEE_ALG_RSA_PKCS1_V1_5;
    } else if (key->key_type == TEE_KEY_TYPE_ECC_P256) {
        sigctx->alg = TEE_ALG_ECDSA_P256;
    } else if (key->key_type == TEE_KEY_TYPE_ECC_P384) {
        sigctx->alg = TEE_ALG_ECDSA_P384;
    }

    return 1;
}

int tee_signature_verify(void *ctx, const unsigned char *sig, size_t siglen,
                         const unsigned char *tbs, size_t tbslen) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;

    if (sigctx == NULL || sigctx->key == NULL) {
        return 0;
    }

    if (sigctx->operation != 2) {
        tee_provider_set_error(TEE_ERR_INVALID_PARAMETER, "Not in verify mode");
        return 0;
    }

    if (!g_tee_interface || !g_tee_interface->verify) {
        tee_provider_set_error(TEE_ERR_TEE_OPERATION, "TEE interface not available");
        return 0;
    }

    // 执行验证
    int ret = g_tee_interface->verify(sigctx->key->key_id, sigctx->alg,
                                      tbs, tbslen, sig, siglen);
    
    return (ret == 0) ? 1 : 0;
}

void tee_signature_freectx(void *ctx) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    if (sigctx) {
        free(sigctx);
    }
}

void *tee_signature_dupctx(void *ctx) {
    TEE_SIG_CTX *src = (TEE_SIG_CTX *)ctx;
    TEE_SIG_CTX *dst;

    if (src == NULL) {
        return NULL;
    }

    dst = calloc(1, sizeof(TEE_SIG_CTX));
    if (dst == NULL) {
        return NULL;
    }

    *dst = *src;
    return dst;
}

int tee_signature_get_ctx_params(void *ctx, OSSL_PARAM *params) {
    TEE_SIG_CTX *sigctx = (TEE_SIG_CTX *)ctx;
    OSSL_PARAM *p;

    if (sigctx == NULL) {
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, "TEE")) {
        return 0;
    }

    return 1;
}

const OSSL_PARAM *tee_signature_gettable_ctx_params(void *ctx, void *provctx) {
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END
    };
    return gettable;
}

int tee_signature_set_ctx_params(void *ctx, const OSSL_PARAM params[]) {
    // TEE签名算法目前不支持设置参数
    return 1;
}

const OSSL_PARAM *tee_signature_settable_ctx_params(void *ctx, void *provctx) {
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_END
    };
    return settable;
}

// ========================== 算法描述表 ==========================

// RSA签名算法分发表
static const OSSL_DISPATCH tee_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))tee_signature_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))tee_signature_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))tee_signature_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))tee_signature_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))tee_signature_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))tee_signature_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))tee_signature_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))tee_signature_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))tee_signature_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))tee_signature_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))tee_signature_settable_ctx_params },
    { 0, NULL }
};

// 密钥管理分发表
static const OSSL_DISPATCH tee_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))tee_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))tee_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))tee_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))tee_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))tee_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))tee_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))tee_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))tee_keymgmt_export_types },
    { 0, NULL }
};

// 支持的算法列表
const OSSL_ALGORITHM tee_signature_algorithms[] = {
    { "RSA", "provider=tee", tee_rsa_signature_functions },
    { "ECDSA", "provider=tee", tee_rsa_signature_functions },
    { NULL, NULL, NULL }
};

const OSSL_ALGORITHM tee_keymgmt_algorithms[] = {
    { "RSA", "provider=tee", tee_keymgmt_functions },
    { "EC", "provider=tee", tee_keymgmt_functions },
    { NULL, NULL, NULL }
};

// ========================== TEE接口初始化 ==========================

// 外部TEE接口实现（将在其他文件中实现）
extern const TEE_Interface *get_tee_interface(void);

int tee_interface_init(void) {
    if (g_tee_interface == NULL) {
        g_tee_interface = get_tee_interface();
        if (g_tee_interface == NULL) {
            return 0;
        }
    }
    
    if (g_tee_interface->init) {
        return g_tee_interface->init() == 0 ? 1 : 0;
    }
    
    return 1;
}