#include "tee_provider.h"
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <string.h>
#include <stdio.h>

// TEE Provider 上下文结构
typedef struct {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    
    // 核心函数指针
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx;
    OSSL_FUNC_core_new_error_fn *c_new_error;
    OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug;
    OSSL_FUNC_core_vset_error_fn *c_vset_error;
} TEE_PROV_CTX;

// 静态全局Provider上下文
static TEE_PROV_CTX *global_provctx = NULL;

// TEE接口指针
extern const TEE_Interface *g_tee_interface;

// Provider参数获取函数
static int tee_provider_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;
    
    p = OSSL_PARAM_locate(params, "name");
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "TEE Provider"))
        return 0;
    
    p = OSSL_PARAM_locate(params, "version");
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0.0"))
        return 0;
    
    p = OSSL_PARAM_locate(params, "buildinfo");
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "TEE Provider for OpenSSL 3.0"))
        return 0;
    
    return 1;
}

// Provider可获取的参数描述
static const OSSL_PARAM tee_provider_gettable_params_table[] = {
    OSSL_PARAM_utf8_ptr("name", NULL, 0),
    OSSL_PARAM_utf8_ptr("version", NULL, 0),
    OSSL_PARAM_utf8_ptr("buildinfo", NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *tee_provider_gettable_params(void *provctx) {
    return tee_provider_gettable_params_table;
}

// 操作查询函数 - 返回Provider支持的算法
static const OSSL_ALGORITHM *tee_provider_query_operation(void *provctx, int operation_id, int *no_cache) {
    *no_cache = 0;
    
    switch (operation_id) {
        case OSSL_OP_SIGNATURE:
            return tee_signature_algorithms;
        case OSSL_OP_KEYMGMT:
            return tee_keymgmt_algorithms;
        default:
            return NULL;
    }
}

// Provider清理函数
static void tee_provider_teardown(void *provctx) {
    TEE_PROV_CTX *ctx = (TEE_PROV_CTX *)provctx;
    
    if (ctx == global_provctx) {
        global_provctx = NULL;
    }
    
    // 清理TEE接口
    if (g_tee_interface) {
        g_tee_interface->cleanup();
    }
    
    free(ctx);
}

// Provider自测试函数
static int tee_provider_self_test(void *provctx) {
    // 执行基本的TEE功能测试
    if (!g_tee_interface || !g_tee_interface->init) {
        return 0;
    }
    
    // 测试TEE接口基本功能
    return g_tee_interface->self_test ? g_tee_interface->self_test() : 1;
}

// Provider函数分发表
static const OSSL_DISPATCH tee_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))tee_provider_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))tee_provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))tee_provider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))tee_provider_query_operation },
    { OSSL_FUNC_PROVIDER_SELF_TEST, (void (*)(void))tee_provider_self_test },
    { 0, NULL }
};

// Provider初始化函数
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx) {
    TEE_PROV_CTX *ctx;
    const OSSL_DISPATCH *fns;
    
    // 分配Provider上下文
    ctx = calloc(1, sizeof(TEE_PROV_CTX));
    if (ctx == NULL) {
        return 0;
    }
    
    ctx->handle = handle;
    
    // 获取核心函数指针
    for (fns = in; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
            case OSSL_FUNC_CORE_GET_LIBCTX:
                ctx->c_get_libctx = OSSL_FUNC_core_get_libctx(fns);
                break;
            case OSSL_FUNC_CORE_NEW_ERROR:
                ctx->c_new_error = OSSL_FUNC_core_new_error(fns);
                break;
            case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
                ctx->c_set_error_debug = OSSL_FUNC_core_set_error_debug(fns);
                break;
            case OSSL_FUNC_CORE_VSET_ERROR:
                ctx->c_vset_error = OSSL_FUNC_core_vset_error(fns);
                break;
            default:
                break;
        }
    }
    
    // 获取库上下文
    if (ctx->c_get_libctx) {
        ctx->libctx = (OSSL_LIB_CTX *)ctx->c_get_libctx(handle);
    }
    
    // 初始化TEE接口
    if (!tee_interface_init()) {
        free(ctx);
        return 0;
    }
    
    // 设置全局Provider上下文
    global_provctx = ctx;
    
    // 返回Provider函数分发表
    *out = tee_provider_functions;
    *provctx = ctx;
    
    return 1;
}

// 错误报告辅助函数
void tee_provider_set_error(int reason, const char *fmt, ...) {
    if (global_provctx && global_provctx->c_new_error && 
        global_provctx->c_set_error_debug && global_provctx->c_vset_error) {
        
        va_list args;
        
        global_provctx->c_new_error(global_provctx->handle);
        global_provctx->c_set_error_debug(global_provctx->handle, __FILE__, __LINE__, __func__);
        
        va_start(args, fmt);
        global_provctx->c_vset_error(global_provctx->handle, reason, fmt, args);
        va_end(args);
    }
}

// 获取Provider上下文
TEE_PROV_CTX *tee_provider_get_ctx(void) {
    return global_provctx;
}