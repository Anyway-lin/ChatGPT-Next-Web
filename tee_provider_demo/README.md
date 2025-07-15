# TEE Provider OpenSSL 3.x 演示

这是一个完整的 TEE (Trusted Execution Environment) Provider 演示项目，模拟在可信执行环境中进行密钥操作，确保私钥不会暴露到 TEE 外部。

## 项目特性

- **零信任密钥管理**: 模拟 TPM2 Provider 架构，私钥操作在 TEE 内部完成
- **OpenSSL 3.x 兼容**: 基于 OpenSSL 3.x Provider 架构
- **完整证书链**: 支持根证书、中间证书、设备证书的完整验证
- **TLS 握手拦截**: 在握手过程中使用 TEE Provider 进行密钥操作
- **安全签名**: 签名操作完全在模拟的 TEE 环境中执行

## 架构设计

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   TLS Client    │    │   TEE Provider   │    │   Test Server   │
│                 │    │                  │    │                 │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │ SSL Context │ │    │ │ Key Mgmt     │ │    │ │ SSL Context │ │
│ └─────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
│        │        │    │ ┌──────────────┐ │    │        │        │
│        │        │◄──►│ │ Signature    │ │    │        │        │
│        │        │    │ │ Operations   │ │    │        │        │
│        │        │    │ └──────────────┘ │    │        │        │
│        │        │    │ ┌──────────────┐ │    │        │        │
│        │        │    │ │ TEE Secure   │ │    │        │        │
│        │        │    │ │ Operations   │ │    │        │        │
│        │        │    │ └──────────────┘ │    │        │        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         └────────── TLS 握手 ─────────────────────────────┘
```

## 文件结构

```
tee_provider_demo/
├── tee_provider.h          # TEE Provider 头文件
├── tee_provider.c          # TEE Provider 实现
├── tls_client.c            # TLS 客户端
├── test_server.c           # 测试服务器
├── generate_certs.sh       # 证书生成脚本
├── run_demo.sh            # 演示运行脚本
├── CMakeLists.txt         # CMake 构建文件
└── README.md              # 文档
```

## 系统要求

- **操作系统**: Ubuntu 20.04+ 或其他现代 Linux 发行版
- **OpenSSL**: 3.0 或更高版本
- **编译器**: GCC 9+ 或 Clang 10+
- **构建工具**: CMake 3.10+
- **依赖库**: libssl-dev, libcrypto-dev, pthread

### 安装依赖 (Ubuntu)

```bash
sudo apt update
sudo apt install -y build-essential cmake libssl-dev pkg-config
```

## 快速开始

### 1. 一键运行演示

```bash
chmod +x run_demo.sh
./run_demo.sh
```

这将自动执行以下步骤：
- 检查系统依赖
- 生成测试证书
- 编译项目
- 启动测试服务器
- 运行 TLS 客户端连接

### 2. 手动步骤

#### 生成证书

```bash
chmod +x generate_certs.sh
./generate_certs.sh
```

#### 编译项目

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

#### 运行演示

```bash
# 终端 1: 启动服务器
cd build
./test_server 8443

# 终端 2: 运行客户端
cd build
./tls_client 127.0.0.1 8443
```

## 详细使用说明

### run_demo.sh 选项

```bash
./run_demo.sh [选项]

选项:
  -h, --help          显示帮助信息
  -c, --clean         清理旧文件后退出
  -b, --build-only    仅编译项目
  -s, --server-only   仅启动服务器
  -p, --port PORT     指定服务器端口 (默认: 8443)
  --host HOST         指定连接主机 (默认: 127.0.0.1)
  --no-demo           不运行演示

环境变量:
  TEE_DEBUG=1         启用详细调试输出
```

### 证书结构

生成的证书链包括：

1. **根 CA 证书** (`root_ca_cert.pem`) - 证书链的信任根
2. **中间 CA 证书** (`intermediate_ca_cert.pem`) - 由根 CA 签发
3. **设备证书** (`device_cert.pem`) - 客户端使用，由中间 CA 签发
4. **服务器证书** (`server_cert.pem`) - 服务器使用，由中间 CA 签发
5. **完整证书链** (`cert_chain.pem`) - 包含设备、中间、根证书

## TEE Provider 工作原理

### 1. Provider 注册

TEE Provider 在 OpenSSL 库中注册为自定义 Provider，提供以下功能：

- **密钥管理** (`OSSL_OP_KEYMGMT`)
- **签名操作** (`OSSL_OP_SIGNATURE`)

### 2. 密钥加载

```c
// 从文件加载私钥到 TEE 环境
int tee_load_private_key_from_file(const char *filename, TEE_KEY **key);
```

私钥被加载到 TEE_KEY 结构中，模拟在安全环境中存储：

```c
typedef struct tee_key_st {
    int key_type;               // 密钥类型 (EVP_PKEY_RSA等)
    int key_size;               // 密钥长度
    EVP_PKEY *pkey;            // OpenSSL私钥对象
    char *key_id;              // 密钥标识符
    int ref_count;             // 引用计数
} TEE_KEY;
```

### 3. 安全签名操作

```c
// 在 TEE 环境中执行签名操作
int tee_simulate_secure_operation(TEE_KEY *key, 
                                  const unsigned char *data, 
                                  size_t data_len, 
                                  unsigned char **result, 
                                  size_t *result_len);
```

所有签名操作都通过这个函数进行，确保私钥不暴露到 TEE 外部。

### 4. TLS 握手流程

```
客户端                    TEE Provider                    服务器
   │                           │                           │
   ├─ SSL_connect() ──────────┐│                           │
   │                          ││                           │
   │  ┌─ 需要客户端证书 ◄──────┘│                           │
   │  │                        │                           │
   │  ├─ 加载证书链 ────────────┤                           │
   │  │                        │                           │
   │  ├─ 需要私钥签名 ──────────┤                           │
   │  │                        │                           │
   │  │              ┌─ TEE 安全签名 ◄─┐                   │
   │  │              │                 │                   │
   │  │              └─ 返回签名结果 ──┘                   │
   │  │                        │                           │
   │  └─ 完成握手 ─────────────────────────────────────────┤
   │                           │                           │
   ├─ 发送 HTTP 请求 ─────────────────────────────────────┤
   │                           │                           │
   ├─ 接收响应 ◄─────────────────────────────────────────┤
   │                           │                           │
```

## 安全特性

### 1. 私钥保护

- 私钥在 TEE_KEY 结构中封装
- 所有密钥操作通过 TEE Provider 接口
- 实际的私钥材料不直接暴露给应用层

### 2. 证书验证

- 完整的证书链验证
- 支持客户端和服务器双向认证
- 证书与私钥匹配性检查

### 3. 调试和监控

```bash
# 启用详细调试输出
TEE_DEBUG=1 ./run_demo.sh
```

调试输出包括：
- Provider 初始化过程
- 密钥加载状态
- 签名操作详情
- TLS 握手步骤

## 故障排除

### 1. 编译错误

**错误**: `fatal error: openssl/core.h: No such file or directory`

**解决**:
```bash
sudo apt install libssl-dev
# 或者检查 OpenSSL 版本
openssl version
```

### 2. 运行时错误

**错误**: `Failed to load TEE provider`

**解决**:
- 确保在正确目录中运行
- 检查库链接: `ldd build/tls_client`

**错误**: `Connection refused`

**解决**:
- 确保服务器正在运行
- 检查端口是否被占用: `netstat -an | grep 8443`

### 3. 证书错误

**错误**: `certificate verify failed`

**解决**:
```bash
# 重新生成证书
./run_demo.sh -c  # 清理
./generate_certs.sh
```

## 开发指南

### 扩展 TEE Provider

1. **添加新的密钥类型**:
   ```c
   // 在 tee_provider.c 中添加 ECC 支持
   case EVP_PKEY_EC:
       // ECC 密钥处理逻辑
   ```

2. **实现加密操作**:
   ```c
   // 添加 OSSL_OP_ASYM_CIPHER 支持
   const OSSL_DISPATCH tee_asym_cipher_functions[] = {
       { OSSL_FUNC_ASYM_CIPHER_NEWCTX, ... },
       // ...
   };
   ```

3. **集成硬件 TEE**:
   - 替换 `tee_simulate_secure_operation` 
   - 使用真实的 TEE API (如 OP-TEE, TrustZone)

### 测试扩展

```bash
# 运行 CMake 测试
cd build
ctest -V

# 自定义测试
./tls_client localhost 8443  # 不同主机
./test_server 9443          # 不同端口
```

## 性能考虑

- TEE 操作通常比普通密码操作慢
- 可以通过缓存和批处理优化
- 在生产环境中需要考虑并发处理

## 安全注意事项

- 这是一个演示项目，不应在生产环境中直接使用
- 真实的 TEE 实现需要硬件支持
- 私钥文件在演示中仍然存储在文件系统中

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License - 详见 LICENSE 文件

## 相关资源

- [OpenSSL 3.0 Provider Architecture](https://www.openssl.org/docs/man3.0/man7/provider.html)
- [OP-TEE Documentation](https://optee.readthedocs.io/)
- [TPM2 Software Stack](https://github.com/tpm2-software/tpm2-tss)

---

*最后更新: $(date)*