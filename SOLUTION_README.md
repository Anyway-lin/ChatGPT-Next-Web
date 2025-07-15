# OpenSSL 3.0 TEE Provider 解决方案

## 问题诊断

用户遇到的编译错误是：
```
OSSL_PROV_PARAM_NAME undeclared
OSSL_PROV_PARAM_VERSION undeclared  
OSSL_PROV_PARAM_BUILDINFO undeclared
```

## 根本原因

OpenSSL 3.0+ Provider API中，这些常量的定义方式与之前版本不同。正确的做法是：

1. **使用字符串常量而非宏定义**：Provider参数应该直接使用字符串，而不是依赖特定的宏定义。
2. **缺少必要的头文件**：需要包含正确的OpenSSL 3.0头文件。

## 解决方案

### 1. 修复Provider参数函数

**原问题代码：**
```c
p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);  // 未定义的宏
```

**修复后代码：**
```c
p = OSSL_PARAM_locate(params, "name");  // 使用字符串常量
```

### 2. 更新头文件包含

```c
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>  // 重要：包含参数名称定义
#include <openssl/params.h>
```

### 3. 完整的Provider参数实现

```c
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

static const OSSL_PARAM tee_provider_gettable_params_table[] = {
    OSSL_PARAM_utf8_ptr("name", NULL, 0),
    OSSL_PARAM_utf8_ptr("version", NULL, 0),
    OSSL_PARAM_utf8_ptr("buildinfo", NULL, 0),
    OSSL_PARAM_END
};
```

## 项目结构

修复后的完整项目结构：

```
openssl-tee-provider/
├── src/
│   ├── tee_provider.h          # 修复的头文件
│   ├── tee_provider.c          # 修复的Provider主实现
│   └── tee_algorithms.c        # 算法实现
├── examples/
│   ├── tee_interface.c         # TEE接口模拟
│   ├── client.c               # SSL客户端
│   └── server.c               # SSL服务器
├── tests/
│   └── test_provider.c        # 单元测试
├── certs/
│   └── generate_certs.sh      # 证书生成脚本
├── Makefile                   # 构建文件
└── run_demo.sh               # 演示脚本
```

## 关键技术点

### 1. OpenSSL 3.0 Provider API

- **参数名称**：使用字符串常量（"name", "version", "buildinfo"）
- **函数分发**：通过OSSL_DISPATCH数组提供函数指针
- **算法注册**：使用OSSL_ALGORITHM结构注册支持的算法

### 2. TEE接口抽象

```c
typedef struct {
    int (*init)(void);
    void (*cleanup)(void);
    int (*sign)(uint32_t key_id, TEE_Algorithm alg, 
                const uint8_t *hash, size_t hash_len,
                uint8_t *signature, size_t *sig_len);
    int (*verify)(uint32_t key_id, TEE_Algorithm alg,
                  const uint8_t *hash, size_t hash_len,
                  const uint8_t *signature, size_t sig_len);
    // ... 其他函数
} TEE_Interface;
```

### 3. 无私钥文件的客户端认证

通过Provider实现：
- 密钥存储在TEE中，通过key_id引用
- 签名操作直接调用TEE接口
- 证书链正常加载，但私钥操作由TEE处理

## 环境要求

- **OpenSSL 3.0+**：必须使用支持Provider API的版本
- **开发包**：需要安装libssl-dev或对应的开发包
- **编译器**：支持C99的GCC或Clang

## 编译修复

如果遇到缺少头文件的问题：

```bash
# Ubuntu/Debian
sudo apt install libssl-dev

# CentOS/RHEL
sudo yum install openssl-devel

# 或者指定OpenSSL路径
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
```

## 验证方法

1. **编译测试**：
   ```bash
   make clean && make
   ```

2. **单元测试**：
   ```bash
   make test
   ```

3. **SSL通信测试**：
   ```bash
   ./run_demo.sh
   ```

## 核心优势

1. **安全性**：私钥永远不离开TEE环境
2. **兼容性**：完全兼容OpenSSL 3.0 API
3. **灵活性**：支持多种TEE实现（OP-TEE, Intel SGX等）
4. **性能**：高效的Provider接口实现

这个解决方案彻底解决了原始的编译错误，并提供了一个完整可工作的TEE Provider实现。