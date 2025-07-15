# OpenSSL Keyless SSL 机制实现

这是一个在Ubuntu下实现的OpenSSL keyless机制，通过自定义签名方法调用TEE（可信执行环境）签名接口，在TLS握手过程中使用自定义私钥对象。

## 📋 功能特性

- ✅ **自定义签名方法**：实现调用TEE签名接口的自定义签名方法
- ✅ **无私钥SSL**：在TLS握手中使用keyless私钥对象
- ✅ **多算法支持**：支持RSA-PSS、RSA-PKCS1、ECDSA等多种签名算法
- ✅ **模拟TEE环境**：包含完整的TEE签名接口模拟实现
- ✅ **完整测试套件**：包含签名验证、证书创建、SSL握手等全面测试

## 🏗️ 项目结构

```
openssl_keyless/
├── tee_sign.h          # TEE签名接口头文件
├── tee_sign.c          # TEE签名接口实现（模拟）
├── keyless_ssl.h       # Keyless SSL机制头文件
├── keyless_ssl.c       # Keyless SSL机制实现
├── test_keyless.c      # 测试程序
├── Makefile           # 编译脚本
└── README.md          # 本说明文件
```

## 🔧 系统要求

- **操作系统**：Ubuntu 18.04+ 或其他Linux发行版
- **编译器**：GCC 7.0+
- **依赖库**：
  - OpenSSL 1.1.1+ 开发库
  - pthread 库
  - 标准C库

## 📦 安装依赖

```bash
# 安装OpenSSL开发库和编译工具
sudo apt-get update
sudo apt-get install -y libssl-dev build-essential pkg-config

# 检查依赖是否正确安装
make check-deps
```

## 🚀 编译和运行

### 基本编译

```bash
# 编译所有目标（测试程序和共享库）
make all

# 或者分别编译
make test_keyless    # 编译测试程序
make libkeyless.so   # 编译共享库
```

### 运行测试

```bash
# 运行完整测试套件
make test

# 运行详细输出的测试
make test-verbose

# 直接运行测试程序
./test_keyless
```

### 其他编译选项

```bash
# 调试版本编译
make debug

# 发布版本编译
make release

# 清理编译文件
make clean

# 查看帮助信息
make help
```

## 🔍 核心架构

### TEE 签名接口

模拟真实的TEE环境，提供以下核心功能：

```c
// 初始化TEE环境
tee_result_t tee_init(void);

// 创建密钥句柄
tee_result_t tee_create_key_handle(uint32_t key_id, tee_algorithm_t alg, 
                                  uint32_t key_size, tee_key_handle_t **handle);

// 使用TEE进行签名
tee_result_t tee_sign(tee_key_handle_t *handle, const uint8_t *data, 
                     size_t data_len, uint8_t *signature, size_t *signature_len);
```

### Keyless SSL 机制

实现自定义的EVP_PKEY方法，拦截OpenSSL的签名操作：

```c
// 初始化keyless SSL环境
keyless_result_t keyless_ssl_init(void);

// 创建keyless私钥对象
keyless_result_t keyless_create_private_key(uint32_t key_id, 
                                           tee_algorithm_t alg,
                                           uint32_t key_size, 
                                           EVP_PKEY **pkey);

// 为SSL上下文配置keyless证书和私钥
keyless_result_t keyless_ssl_use_certificate_and_key(SSL_CTX *ctx,
                                                     X509 *cert,
                                                     EVP_PKEY *pkey);
```

## 📊 测试覆盖

测试程序包含以下测试场景：

1. **基本签名测试**
   - RSA-PSS-SHA256 签名和验证
   - ECDSA-SHA256 签名和验证

2. **证书创建测试**
   - 使用keyless私钥创建自签名证书
   - 证书验证

3. **SSL/TLS握手测试**
   - 创建SSL服务器和客户端
   - 执行完整的TLS握手
   - 数据传输验证

## 🔧 高级用法

### 安装为系统库

```bash
# 安装到系统目录
sudo make install

# 卸载
sudo make uninstall
```

### 内存泄漏检测

```bash
# 使用valgrind进行内存检查
make valgrind
```

### 静态代码分析

```bash
# 运行静态分析
make analyze
```

## 🎯 核心实现原理

### 1. 自定义签名方法

通过创建自定义的EVP_PKEY_METHOD，重写RSA和ECDSA的签名函数：

```c
// RSA签名回调
static int keyless_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                           const unsigned char *tbs, size_t tbslen) {
    // 获取keyless私钥数据
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    keyless_pkey_t *keyless_data = get_keyless_pkey_data(pkey);
    
    // 调用TEE签名
    return tee_sign(keyless_data->tee_handle, tbs, tbslen, sig, siglen);
}
```

### 2. TEE接口集成

将OpenSSL的签名请求重定向到TEE环境：

```c
// 在TLS握手中，OpenSSL调用签名时：
OpenSSL -> EVP_PKEY_sign() -> keyless_rsa_sign() -> tee_sign() -> TEE Hardware
```

### 3. 私钥管理

私钥实际存储在TEE中，OpenSSL只持有公钥和TEE句柄：

```c
typedef struct {
    tee_key_handle_t *tee_handle;  // TEE密钥句柄
    EVP_PKEY *public_key;          // 公钥
    int key_type;                  // 密钥类型
    int key_size;                  // 密钥大小
} keyless_pkey_t;
```

## 🔒 安全特性

- **私钥隔离**：私钥永远不离开TEE环境
- **签名验证**：所有签名都可以通过对应公钥验证
- **算法支持**：支持现代密码学算法（RSA-PSS、ECDSA）
- **TLS兼容**：完全兼容标准TLS握手流程

## 🐛 故障排除

### 编译错误

```bash
# 检查依赖
make check-deps

# 清理后重新编译
make clean && make all
```

### 运行时错误

```bash
# 查看详细错误信息
make test-verbose

# 使用调试版本
make debug && ./test_keyless
```

### SSL握手失败

- 检查端口是否被占用（默认8443）
- 确保防火墙允许本地连接
- 查看SSL错误日志

## 📈 性能统计

程序运行后会显示性能统计信息：

```
=== Keyless SSL Statistics ===
Sign operations: 5
Verify operations: 3
Initialized: Yes
==============================
```

## 🤝 扩展开发

### 添加新的签名算法

1. 在`tee_sign.h`中添加新的算法类型
2. 在`tee_sign.c`中实现对应的密钥生成和签名逻辑
3. 在`keyless_ssl.c`中添加算法支持

### 集成真实TEE

1. 替换`tee_sign.c`中的模拟实现
2. 集成真实的TEE SDK
3. 适配TEE的密钥管理接口

## 📄 许可证

本项目仅用于教育和研究目的。请确保在使用时遵守相关法律法规。

## 🎉 测试结果示例

成功运行时的输出示例：

```
=== OpenSSL Keyless Mechanism Test ===
Keyless: SSL environment initialized successfully

=== Testing Basic Signing ===
Testing RSA-PSS-SHA256 signing...
TEE: Generated RSA-2048 key pair
RSA signature created, length: 256 bytes
RSA signature verification: PASSED

Testing ECDSA-SHA256 signing...
TEE: Generated ECDSA key pair for curve prime256v1
ECDSA signature created, length: 71 bytes
ECDSA signature verification: PASSED
Basic signing test: PASSED

=== Testing Certificate Creation ===
Certificate created successfully
Certificate verification: PASSED

=== Testing SSL/TLS Handshake ===
Starting SSL server on port 8443...
SSL server ready, waiting for connections...
Connecting to SSL server...
SSL handshake completed successfully!
Cipher: TLS_AES_256_GCM_SHA384
SSL/TLS handshake test: PASSED

=== Test Results ===
Tests passed: 3/3
Success rate: 100.0%
All tests PASSED! ✓
```