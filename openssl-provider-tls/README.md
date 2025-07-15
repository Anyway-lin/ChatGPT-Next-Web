# OpenSSL TEE Provider TLS项目

## 项目概述

本项目实现了一个基于OpenSSL 3.x Provider机制的TEE（Trusted Execution Environment）模拟方案，用于在TLS握手过程中安全地处理私钥操作。该方案确保私钥永不离开安全环境，同时保持与标准OpenSSL TLS流程的完全兼容性。

### 核心特性

- **🔐 安全的私钥管理**: 私钥操作在TEE Provider内部完成，应用程序无法直接访问私钥
- **🤝 标准TLS兼容**: 完全兼容OpenSSL TLS客户端和服务器
- **📜 三级证书链**: 支持根证书 → 中间CA → 设备证书的完整信任链
- **🔧 OpenSSL 3.x Provider**: 基于最新的OpenSSL Provider架构
- **✅ 双向认证**: 支持客户端和服务器双向证书验证
- **🛠️ 即用型方案**: 提供完整的构建、测试和演示环境

## 架构设计

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   TLS Client    │    │  TEE Provider   │    │   TLS Server    │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Certificate │ │    │ │ Private Key │ │    │ │ Certificate │ │
│ │    Chain    │ │    │ │  Operations │ │    │ │  & Key Pair │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │                 │
│ │   SSL/TLS   │◄────►│ │   Signing   │ │    │                 │
│ │   Context   │ │    │ │ & Decryption│ │    │                 │
│ └─────────────┘ │    │ └─────────────┘ │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                        │                        │
         └──────── TLS Handshake & Data Exchange ─────────┘
```

## 目录结构

```
openssl-provider-tls/
├── src/                    # 源代码目录
│   ├── tee_provider.c      # TEE Provider实现
│   ├── tls_client.c        # TLS客户端实现
│   └── tls_server.c        # TLS服务器实现
├── scripts/                # 脚本目录
│   └── generate_certs.sh   # 证书生成脚本
├── build/                  # 构建输出目录（运行后生成）
│   ├── libtee_provider.so  # TEE Provider动态库
│   ├── tls_client          # TLS客户端可执行文件
│   └── tls_server          # TLS服务器可执行文件
├── certs/                  # 证书目录（生成后创建）
│   ├── ca-cert.pem         # 根CA证书
│   ├── intermediate-cert.pem # 中间CA证书
│   ├── device-cert.pem     # 设备证书
│   ├── device-chain.pem    # 完整证书链
│   ├── server-cert.pem     # 服务器证书
│   └── *.pem               # 其他证书和密钥文件
├── Makefile                # 构建配置
├── run_demo.sh             # 一键演示脚本
└── README.md               # 项目说明
```

## 快速开始

### 环境要求

- **操作系统**: Ubuntu 18.04+ 或其他Linux发行版
- **编译器**: GCC 7.0+
- **OpenSSL**: 3.0+ (系统自带或手动安装)
- **工具**: make, pkg-config

### 一键运行

```bash
# 克隆或创建项目目录
cd openssl-provider-tls

# 给予执行权限并运行演示
chmod +x run_demo.sh
./run_demo.sh
```

### 手动步骤

#### 1. 安装依赖

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev openssl

# 或使用Makefile
make install-deps
```

#### 2. 编译项目

```bash
# 编译所有组件
make all

# 或分别编译
make provider  # TEE Provider
make client    # TLS客户端
make server    # TLS服务器
```

#### 3. 生成证书

```bash
make certs
```

#### 4. 运行测试

```bash
# 终端1：启动服务器
make test-server

# 终端2：运行客户端
make test-client
```

## 使用说明

### TEE Provider

TEE Provider是本项目的核心组件，实现了OpenSSL 3.x Provider接口：

```c
// 加载TEE Provider
OSSL_PROVIDER *tee_provider = OSSL_PROVIDER_load(NULL, "./build/libtee_provider.so");

// 加载私钥到TEE环境
tee_provider_load_private_key("certs/device-key-nopass.pem");
```

### TLS客户端

客户端使用TEE Provider进行私钥操作：

```bash
./build/tls_client <服务器IP> <端口> <设备私钥> <设备证书链> <CA证书>

# 示例
./build/tls_client 127.0.0.1 8443 \
    certs/device-key-nopass.pem \
    certs/device-chain.pem \
    certs/ca-cert.pem
```

### TLS服务器

服务器用于测试客户端连接：

```bash
./build/tls_server <端口> <服务器证书> <服务器私钥>

# 示例
./build/tls_server 8443 \
    certs/server-cert.pem \
    certs/server-key-nopass.pem
```

## 技术细节

### TEE Provider实现

TEE Provider实现了以下OpenSSL接口：

- **Signature Operations**: 签名和验证操作
- **Key Management**: 密钥加载和管理
- **Provider Interface**: 标准Provider查询和参数接口

```c
// 主要函数
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, ...);
static int tee_signature_sign(void *ctx, unsigned char *sig, ...);
static int tee_signature_verify(void *ctx, const unsigned char *sig, ...);
```

### 证书体系

项目使用三级证书体系：

```
Root CA (根证书)
    ↓ 签发
Intermediate CA (中间证书)
    ↓ 签发
Device Certificate (设备证书)
```

### 安全特性

1. **私钥隔离**: 私钥只在TEE Provider内部处理
2. **标准接口**: 使用OpenSSL标准Provider接口
3. **证书验证**: 支持完整的证书链验证
4. **双向认证**: 客户端和服务器互相验证

## 开发指南

### 扩展TEE Provider

要集成真实的TEE环境，需要修改以下函数：

```c
// 在tee_provider.c中修改
static int tee_sign_operation(const unsigned char *tbs, size_t tbslen,
                             unsigned char *sig, size_t *siglen) {
    // 替换为真实的TEE API调用
    // 例如：调用OPTEE、TrustZone或其他TEE SDK
    return tee_hardware_sign(tbs, tbslen, sig, siglen);
}
```

### 添加新算法

Provider支持扩展其他算法：

```c
static const OSSL_ALGORITHM tee_algorithms[] = {
    { "RSA", "provider=tee-provider", tee_signature_functions, "TEE RSA" },
    { "ECDSA", "provider=tee-provider", tee_ecdsa_functions, "TEE ECDSA" }, // 新增
    { NULL, NULL, NULL, NULL }
};
```

## 故障排除

### 常见问题

1. **编译失败**
   ```bash
   # 检查OpenSSL开发包
   pkg-config --cflags --libs openssl
   
   # 安装开发包
   sudo apt-get install libssl-dev
   ```

2. **Provider加载失败**
   ```bash
   # 检查库文件
   ls -la build/libtee_provider.so
   
   # 检查依赖
   ldd build/libtee_provider.so
   ```

3. **证书验证失败**
   ```bash
   # 验证证书链
   openssl verify -CAfile certs/ca-cert.pem -untrusted certs/intermediate-cert.pem certs/device-cert.pem
   ```

4. **TLS握手失败**
   ```bash
   # 检查服务器日志
   cat server.log
   
   # 使用OpenSSL客户端测试
   openssl s_client -connect 127.0.0.1:8443 -cert certs/device-cert.pem -key certs/device-key-nopass.pem
   ```

### 调试模式

启用详细日志输出：

```bash
# 设置OpenSSL调试
export OPENSSL_TRACE=provider,tls

# 运行客户端
./build/tls_client 127.0.0.1 8443 certs/device-key-nopass.pem certs/device-chain.pem certs/ca-cert.pem
```

## 性能优化

### 建议的优化

1. **缓存机制**: 在TEE Provider中实现密钥句柄缓存
2. **异步操作**: 支持异步签名操作
3. **批量处理**: 实现批量签名接口
4. **内存管理**: 优化内存分配和释放

## 安全考虑

### 生产环境部署

1. **真实TEE集成**: 替换模拟TEE为真实硬件TEE
2. **密钥管理**: 实现安全的密钥生成和存储
3. **证书管理**: 建立完整的PKI基础设施
4. **访问控制**: 实现细粒度的访问控制机制

### 安全审计

定期进行以下安全检查：

- 代码安全审计
- 密钥生命周期管理
- 证书有效性验证
- 网络通信安全

## 许可证

本项目基于MIT许可证开源。

## 贡献指南

欢迎提交Issue和Pull Request来改进项目。

## 联系方式

如有问题或建议，请通过以下方式联系：

- 提交GitHub Issue
- 发送邮件到项目维护者

---

**注意**: 本项目仅用于演示和学习目的。在生产环境中使用前，请确保进行充分的安全评估和测试。