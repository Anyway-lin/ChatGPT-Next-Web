# TEE Provider for OpenSSL 3.0.9

基于OpenSSL 3.0.9的TEE (Trusted Execution Environment) Provider实现，支持在没有私钥文件的情况下进行证书链处理和签名操作。

## 功能特性

- ✅ **无私钥文件操作**: 客户端无需存储私钥文件，私钥安全存储在TEE中
- ✅ **证书链完整性**: 解决OpenSSL默认丢弃证书链的问题
- ✅ **TEE接口对接**: 支持自定义TEE签名、验签、加密、解密接口
- ✅ **多算法支持**: 支持RSA和ECDSA签名算法
- ✅ **TLS客户端认证**: 完整支持TLS客户端证书认证
- ✅ **Provider架构**: 基于OpenSSL 3.0原生Provider机制

## 系统要求

- Ubuntu 18.04+ 或类似Linux发行版
- OpenSSL 3.0.9+
- GCC 编译器
- Make 构建工具

## 快速开始

### 1. 检查OpenSSL版本

```bash
openssl version
# 应输出: OpenSSL 3.0.9 或更高版本
```

### 2. 编译和安装

```bash
# 克隆或下载项目文件
# cd tee-provider

# 编译TEE Provider
make

# 生成测试证书
make setup-test

# 运行测试
make test
```

### 3. 基本使用

```bash
# 设置环境变量
export OPENSSL_CONF=$(pwd)/tee_openssl.cnf
export TEE_PRIVATE_KEY=$(pwd)/tee_private_key.pem
export TEE_CERTIFICATE=$(pwd)/tee_certificate.pem

# 使用TEE密钥进行签名
echo "Hello TEE" > data.txt
openssl pkeyutl -provider tee -provider default \
    -inkey "tee:device_rsa" \
    -sign -in data.txt -out signature.bin

# 验证签名
openssl pkeyutl -provider default \
    -pubin -inkey <(openssl pkey -in tee_private_key.pem -pubout) \
    -verify -in data.txt -sigfile signature.bin
```

## 文件结构

```
tee-provider/
├── tee_provider.c          # TEE Provider主要实现
├── Makefile               # 编译脚本
├── tee_openssl.cnf        # OpenSSL配置文件
├── setup_test_certs.sh    # 测试证书生成脚本
├── test_tee_provider.sh   # 功能测试脚本
├── test_client.c          # C语言测试客户端
└── README.md             # 使用说明
```

## 详细使用说明

### Provider配置

TEE Provider通过OpenSSL配置文件加载：

```ini
# tee_openssl.cnf
[provider_sect]
tee = tee_sect
default = default_sect

[tee_sect]
identity = tee
module = ./tee_provider.so
activate = 1
```

### 密钥引用格式

TEE密钥使用URI格式引用：
- `tee:device_rsa` - TEE中的RSA密钥
- `tee:device_ec` - TEE中的EC密钥
- `tee:key_id` - 任意TEE密钥标识符

### 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `TEE_PRIVATE_KEY` | TEE私钥文件路径(模拟) | `./tee_private_key.pem` |
| `TEE_CERTIFICATE` | TEE证书文件路径 | `./tee_certificate.pem` |
| `OPENSSL_CONF` | OpenSSL配置文件 | 无 |

### C语言编程接口

```c
#include <openssl/provider.h>
#include <openssl/evp.h>

// 加载TEE Provider
OSSL_PROVIDER *tee_prov = OSSL_PROVIDER_load(NULL, "tee");
OSSL_PROVIDER *default_prov = OSSL_PROVIDER_load(NULL, "default");

// 使用TEE密钥进行签名
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=tee");
EVP_PKEY_sign_init(ctx);
EVP_PKEY_sign(ctx, signature, &sig_len, data, data_len);
```

## 测试说明

### 测试证书链

项目会生成完整的三级证书链：
1. `root_ca_cert.pem` - 根CA证书
2. `intermediate_ca_cert.pem` - 中间CA证书  
3. `tee_certificate.pem` - 设备证书
4. `tee_cert_chain.pem` - 完整证书链

### 功能测试

运行 `make test` 执行以下测试：
- Provider加载测试
- 密钥管理测试
- 签名功能测试
- 证书链处理测试
- TLS客户端认证测试

### 手动测试

```bash
# 编译测试客户端
gcc -o test_client test_client.c -lssl -lcrypto

# 运行基本测试
./test_client

# 运行TLS测试
./test_client --tls-test
```

## TEE接口层说明

当前实现包含模拟的TEE接口层，实际部署时需要替换为真实的TEE接口：

```c
// 需要实现的TEE接口
static int tee_sign_data(const char *key_id, 
                        const unsigned char *data, 
                        size_t data_len, 
                        unsigned char **signature, 
                        size_t *sig_len);

static EVP_PKEY *tee_get_public_key(const char *key_id);

static int tee_encrypt_data(const char *key_id, 
                           const unsigned char *plaintext,
                           size_t plaintext_len,
                           unsigned char **ciphertext,
                           size_t *ciphertext_len);

static int tee_decrypt_data(const char *key_id,
                           const unsigned char *ciphertext,
                           size_t ciphertext_len, 
                           unsigned char **plaintext,
                           size_t *plaintext_len);
```

## 部署指南

### 1. 生产环境部署

```bash
# 编译release版本
make clean && make

# 安装到系统目录
sudo make install

# 配置系统级OpenSSL
sudo cp tee_openssl.cnf /etc/ssl/openssl_tee.cnf
```

### 2. 集成到应用

```c
// 应用启动时
OSSL_PROVIDER_load(NULL, "tee");
OSSL_PROVIDER_load(NULL, "default");

// 设置环境变量
setenv("OPENSSL_CONF", "/path/to/tee_openssl.cnf", 1);

// 使用TEE密钥
SSL_CTX_use_PrivateKey_file(ctx, "tee:device_key", SSL_FILETYPE_PEM);
```

### 3. 配置管理

建议将TEE相关配置集中管理：

```bash
# /etc/tee/config
TEE_KEY_PREFIX=device_
TEE_PROVIDER_PATH=/usr/local/lib/ossl-modules/tee_provider.so
TEE_CERTIFICATE_STORE=/etc/tee/certs/
```

## 故障排除

### 常见问题

1. **Provider加载失败**
   ```bash
   # 检查共享库依赖
   ldd tee_provider.so
   
   # 检查OpenSSL配置
   openssl list -providers -verbose
   ```

2. **密钥加载失败**
   ```bash
   # 检查环境变量
   echo $TEE_PRIVATE_KEY
   echo $OPENSSL_CONF
   
   # 检查文件权限
   ls -la *.pem
   ```

3. **签名操作失败**
   ```bash
   # 启用调试输出
   export OPENSSL_DEBUG=1
   
   # 查看详细错误
   openssl pkeyutl -provider tee -provider default \
       -inkey "tee:device_rsa" -sign -in data.txt 2>&1
   ```

### 调试模式

```bash
# 编译调试版本
make debug

# 启用详细日志
export TEE_DEBUG=1
export OPENSSL_DEBUG=1
```

## 安全考虑

1. **私钥保护**: 真实环境中私钥应存储在硬件TEE中，不应以文件形式存在
2. **证书验证**: 应验证完整的证书链，包括根CA的可信性
3. **通信安全**: TEE通信应使用安全通道，防止中间人攻击
4. **密钥轮换**: 定期更新密钥和证书，实现密钥生命周期管理

## 性能优化

1. **密钥缓存**: 缓存从TEE获取的公钥，减少TEE访问次数
2. **批量操作**: 支持批量签名操作，提高吞吐量
3. **异步处理**: 支持异步TEE操作，避免阻塞主线程

## 贡献指南

欢迎提交Issue和Pull Request！

1. Fork项目
2. 创建功能分支
3. 提交更改
4. 发起Pull Request

## 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 联系方式

如有问题或建议，请通过以下方式联系：
- 提交GitHub Issue
- 发送邮件至项目维护者

---

**注意**: 这是一个演示实现，生产环境使用前请进行充分的安全评估和测试。
