# 🚀 TEE Provider V2 快速使用指南

## 🎯 核心特性
- ✅ **无私钥文件加载**：客户端代码完全不访问私钥文件
- ✅ **TEE签名回调**：所有签名操作通过TEE接口完成
- ✅ **证书链保护**：完整的密钥管理，不丢弃证书链
- ✅ **即开即用**：3步完成集成

## ⚡ 快速开始

### 1. 编译项目
```bash
cd /workspace/openssl-tls-provider
make all
```

### 2. 运行基础测试
```bash
# 测试TEE Provider基础功能
./build/test_tee_v2_simple
```

### 3. 运行完整TLS演示
```bash
# 启动服务器
./build/tls_server &

# 运行TEE客户端（无私钥文件）
./build/tls_client_v2
```

## 📋 核心API使用

### 1. 初始化TEE Provider
```c
#include "tee_provider_v2.h"

// 创建OpenSSL上下文
OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();

// 加载TEE Provider
OSSL_PROVIDER_add_builtin(libctx, "tee", OSSL_provider_init);
OSSL_PROVIDER *tee_prov = OSSL_PROVIDER_load(libctx, "tee");
```

### 2. 配置TEE（不加载私钥）
```c
// 仅使用证书路径配置TEE（私钥在TEE中）
if (!tee_provider_configure("./certs/client.pem")) {
    // 配置失败
}
```

### 3. 创建TEE密钥对象
```c
// 创建与TEE绑定的密钥对象（私钥保护在TEE中）
EVP_PKEY *tee_key = tee_provider_create_key(libctx);

// 在SSL中使用TEE密钥
SSL_CTX_use_PrivateKey(ssl_ctx, tee_key);
```

## 🔄 TEE接口对接

### 替换为真实TEE的步骤：

1. **修改TEE签名接口** (`src/tee_provider_v2.c`):
```c
static int tee_interface_sign(const char *key_id, const unsigned char *digest, 
                             size_t digest_len, unsigned char *signature, 
                             size_t *sig_len) {
    // 替换这里为您的TEE API调用
    // 例如：return your_tee_sign_api(key_id, digest, digest_len, signature, sig_len);
}
```

2. **扩展TEE接口**：
```c
// 添加其他TEE操作
static int tee_interface_verify(...);   // 验签
static int tee_interface_encrypt(...);  // 加密  
static int tee_interface_decrypt(...);  // 解密
```

## 📁 项目结构
```
openssl-tls-provider/
├── src/
│   ├── tee_provider_v2.c      # 核心TEE Provider实现
│   ├── tee_provider_v2.h      # API接口定义
│   ├── tls_client_v2.c        # 无私钥文件的TLS客户端
│   └── test_tee_v2_simple.c   # 基础功能测试
├── build/
│   ├── libtee_provider_v2.so  # TEE Provider共享库
│   ├── tls_client_v2          # 演示客户端程序
│   └── test_tee_v2_simple     # 测试程序
└── certs/                     # 测试证书（仅用于演示）
```

## 🔍 验证成功标志

### TEE Provider加载成功：
```
[TEE-V2] 🚀 TEE Provider V2 初始化开始
[TEE-V2] ✅ TEE Provider V2 初始化完成
```

### TEE配置成功：
```
[TEE-V2] ✅ TEE Provider配置成功
[TEE-V2]    TEE密钥ID: tee_key_client.pem
[TEE-V2]    密钥大小: 2048 bits
```

### TEE密钥创建成功：
```
[TEE-V2] ✅ TEE密钥创建成功
[TEE-V2]    密钥已绑定到TEE Provider
[TEE-V2]    私钥操作将调用TEE接口
```

### TEE回调函数调用：
```
[TEE-V2] 🔑 密钥管理：从参数创建TEE密钥
[TEE-V2] 🔑 密钥管理：检查密钥能力
[TEE-V2] 🔑 密钥管理：匹配密钥
```

## ⚠️ 重要说明

### 安全特性
- **私钥隔离**：私钥永远不出现在客户端内存中
- **TEE保护**：所有私钥操作都在TEE安全环境中执行
- **密钥引用**：客户端只持有密钥ID，不是实际密钥

### 生产使用
- 将`tee_interface_sign`替换为您的TEE API
- 根据需要添加密钥管理、证书验证等功能
- 考虑添加TEE硬件错误处理和重试机制

## 🎯 成功集成检查清单

- [ ] TEE Provider成功加载 
- [ ] TEE配置不需要私钥文件
- [ ] TEE密钥对象创建成功
- [ ] SSL上下文接受TEE密钥
- [ ] 所有TEE回调函数被调用
- [ ] 客户端代码无私钥文件访问

## 🔗 相关文档

- `TEE_SOLUTION_COMPLETE.md` - 完整技术解决方案
- `README.md` - 详细使用说明
- `src/tee_provider_v2.h` - API接口文档

---

**🎉 恭喜！您现在拥有了完整的OpenSSL 3.x TEE Provider解决方案！**