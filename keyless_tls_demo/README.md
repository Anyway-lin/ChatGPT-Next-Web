# Keyless TLS Demo - 零信任密钥管理系统

本项目实现了一个基于OpenSSL 3.x的零信任密钥管理系统，模拟TEE环境下的密钥操作，并通过自定义Provider实现keyless TLS握手。

## 项目目标

解决OpenSSL 3.x中客户端没有密钥文件或密钥类型和证书类型不匹配时遗弃证书链的问题，通过TEE接口实现真正的零信任密钥管理。

## 架构设计

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   TLS Client    │    │   TLS Server     │    │  Certificate    │
│                 │    │                  │    │   Authority     │
│ ┌─────────────┐ │    │ ┌──────────────┐ │    │                 │
│ │   OpenSSL   │ │    │ │   OpenSSL    │ │    │  ┌───────────┐  │
│ │   3.x SSL   │ │    │ │   Standard   │ │    │  │Root CA    │  │
│ │   Context   │ │    │ │   SSL        │ │    │  │           │  │
│ └─────────────┘ │    │ └──────────────┘ │    │  │Intermediate│  │
│        │        │    │                  │    │  │CA         │  │
│ ┌─────────────┐ │    └──────────────────┘    │  │           │  │
│ │  Keyless    │ │                            │  │Device     │  │
│ │  Provider   │ │                            │  │Certificate│  │
│ └─────────────┘ │                            │  └───────────┘  │
│        │        │                            └─────────────────┘
│ ┌─────────────┐ │
│ │ TEE Mock    │ │
│ │ Interface   │ │
│ └─────────────┘ │
└─────────────────┘
```

### 核心组件

1. **TEE Mock Interface** (`tee_mock.c/h`)
   - 模拟TEE环境的签名验签、加密解密接口
   - 实现`TeeKeylessOperation`函数
   - 支持RSA PKCS#1 v1.5和OAEP填充

2. **Keyless Provider** (`keyless_provider.c/h`)
   - OpenSSL 3.x自定义Provider实现
   - 集成TEE接口到OpenSSL密钥操作中
   - 支持RSA签名和非对称解密

3. **TLS Client** (`tls_client.c`)
   - 使用keyless provider的TLS客户端
   - 证书链发送但私钥操作通过TEE完成
   - 支持双向TLS认证

4. **TLS Server** (`tls_server.c`)
   - 标准TLS服务器实现
   - 支持客户端证书验证
   - 用于测试keyless客户端

## 功能特性

- ✅ OpenSSL 3.x Provider模型集成
- ✅ TEE接口模拟（签名、解密）
- ✅ 三级证书链支持（Root CA → Intermediate CA → Device Certificate）
- ✅ TLS 1.2/1.3双向认证
- ✅ RSA PKCS#1 v1.5和OAEP填充模式
- ✅ 零私钥泄露的安全设计
- ✅ 完整的测试框架

## 快速开始

### 1. 安装依赖

```bash
# Ubuntu/Debian
make install-deps

# 或手动安装
sudo apt-get install build-essential libssl-dev pkg-config
```

### 2. 检查依赖

```bash
make check-deps
```

### 3. 编译项目

```bash
make all
```

这将自动：
- 生成测试证书（Root CA → Intermediate CA → Device Certificate）
- 编译所有组件
- 创建可执行文件

### 4. 运行基础测试

```bash
make test
```

### 5. 运行TLS演示

**终端1（服务器）：**
```bash
./tls_server
```

**终端2（客户端）：**
```bash
./tls_client
```

### 6. 自动化测试

```bash
make test-tls
```

## 详细使用说明

### 证书结构

项目会自动生成以下证书文件：

```
certs/
├── root_ca_cert.pem           # 根证书
├── root_ca_key.pem            # 根证书私钥
├── intermediate_ca_cert.pem   # 中间证书
├── intermediate_ca_key.pem    # 中间证书私钥
├── device_cert.pem           # 设备证书（用于客户端）
├── device_key.pem            # 设备私钥（TEE模拟使用）
├── device_chain.pem          # 完整证书链
├── server_cert.pem           # 服务器证书
└── server_key.pem            # 服务器私钥
```

### TEE接口说明

模拟的TEE接口支持以下操作：

```c
// 操作类型
enum TeeKeyPurpose {
    KM_PURPOSE_DECRYPT = 1,     // 使用私钥解密
    KM_PURPOSE_SIGN = 2,        // 使用私钥签名
};

// 填充模式
enum TeePadType {
    KM_PAD_NONE = 1,                    // 无填充
    KM_PAD_RSA_OAEP = 2,               // OAEP填充
    KM_PAD_RSA_PKCS1_1_5_ENCRYPT = 4,  // PKCS#1 v1.5加密填充
    KM_PAD_RSA_PKCS1_1_5_SIGN = 5,     // PKCS#1 v1.5签名填充
};

// 主要接口函数
int32_t TeeKeylessOperation(enum TeeKeyPurpose purpose, uint32_t padType, 
                           struct TeeBlob *inData, struct TeeBlob *outData);
```

### 自定义配置

#### 修改服务器地址和端口

```bash
# 连接到不同服务器
./tls_client 192.168.1.100

# 使用自定义证书路径
./tls_client 127.0.0.1 /path/to/device_key.pem /path/to/device_cert.pem /path/to/ca_cert.pem
```

#### 修改服务器证书

```bash
# 使用自定义服务器证书
./tls_server /path/to/server_cert.pem /path/to/server_key.pem /path/to/ca_cert.pem
```

## 技术实现细节

### 1. Provider注册机制

使用OpenSSL 3.x的内置Provider注册：

```c
OSSL_PROVIDER *keyless_prov = OSSL_PROVIDER_add_builtin(NULL, KEYLESS_PROVIDER_NAME, keyless_provider_init);
OSSL_PROVIDER_activate(keyless_prov);
```

### 2. 密钥操作拦截

通过自定义的签名和解密函数表拦截OpenSSL的密钥操作：

```c
static const OSSL_DISPATCH keyless_rsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))keyless_signature_sign },
    // ...
};
```

### 3. TEE集成

每次需要私钥操作时，调用TEE接口：

```c
int32_t result = TeeKeylessOperation(KM_PURPOSE_SIGN, KM_PAD_RSA_PKCS1_1_5_SIGN, &inData, &outData);
```

### 4. 证书链处理

客户端发送完整证书链，但私钥操作由TEE处理：

```c
SSL_CTX_use_certificate_file(ctx, device_cert_path, SSL_FILETYPE_PEM);
// 私钥操作通过provider重定向到TEE
```

## 安全特性

- **零私钥暴露**：私钥始终在TEE中，应用层无法直接访问
- **证书链验证**：支持完整的证书链验证
- **加密通信**：所有通信通过TLS 1.2/1.3加密
- **身份认证**：双向证书认证确保通信双方身份

## 故障排除

### 编译错误

1. **OpenSSL版本过低**：
   ```bash
   # 检查OpenSSL版本（需要3.0+）
   openssl version
   ```

2. **缺少开发库**：
   ```bash
   sudo apt-get install libssl-dev
   ```

### 运行时错误

1. **证书验证失败**：
   - 检查证书路径是否正确
   - 确认证书链完整性

2. **TEE初始化失败**：
   - 确认设备私钥文件存在且可读
   - 检查文件权限

3. **TLS握手失败**：
   - 确认服务器正在运行
   - 检查防火墙设置

### 调试模式

编译时添加调试信息：

```bash
make CFLAGS="-Wall -Wextra -g -DDEBUG" all
```

## 项目结构

```
keyless_tls_demo/
├── src/                      # 源代码
│   ├── tee_mock.h           # TEE接口头文件
│   ├── tee_mock.c           # TEE接口实现
│   ├── keyless_provider.h   # Provider头文件
│   ├── keyless_provider.c   # Provider实现
│   ├── tls_server.c         # TLS服务器
│   ├── tls_client.c         # Keyless TLS客户端
│   └── test_tee.c           # TEE测试程序
├── scripts/                 # 脚本文件
│   └── generate_certs.sh    # 证书生成脚本
├── certs/                   # 证书目录（自动生成）
├── Makefile                 # 构建脚本
└── README.md               # 本文档
```

## 扩展开发

### 添加新的加密算法

1. 在`tee_mock.c`中添加算法支持
2. 在`keyless_provider.c`中注册新算法
3. 更新函数分发表

### 集成真实TEE

1. 替换`tee_mock.c`中的模拟实现
2. 调用真实的TEE API
3. 处理TEE特定的错误码

### 支持其他证书格式

1. 修改证书加载逻辑
2. 添加格式转换功能
3. 更新配置选项

## 贡献指南

1. Fork项目
2. 创建功能分支
3. 提交更改
4. 发起Pull Request

## 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 技术支持

如有问题或建议，请：
1. 检查本README的故障排除部分
2. 查看项目Issues
3. 提交新Issue描述问题

---

**注意**：本项目仅用于演示和学习目的，生产环境使用需要进一步的安全加固和测试。