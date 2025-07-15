# OpenSSL 3.0.9 TEE Provider 实现

本项目实现了一个自定义的OpenSSL Provider，用于在TEE（Trusted Execution Environment）环境下进行密钥管理和证书操作，解决客户端无私钥文件的问题。

## 项目结构

```
openssl-tee-provider/
├── README.md
├── Makefile
├── src/
│   ├── tee_provider.c          # TEE Provider 主实现
│   ├── tee_keystore.c          # TEE 密钥存储实现
│   ├── tee_signature.c         # TEE 签名算法实现
│   ├── tee_cipher.c            # TEE 加密算法实现
│   └── tee_provider.h          # 头文件
├── examples/
│   ├── client.c                # 客户端示例
│   ├── server.c                # 服务端示例
│   └── tee_interface.c         # TEE接口模拟实现
├── certs/
│   ├── generate_certs.sh       # 证书生成脚本
│   └── openssl.cnf            # OpenSSL配置文件
├── config/
│   └── provider.conf          # Provider配置文件
└── tests/
    └── test_provider.c        # 测试代码
```

## 核心特性

1. **自定义Provider**: 实现OpenSSL 3.0 Provider接口
2. **TEE接口集成**: 支持TEE环境下的签名验签、加密解密
3. **证书链管理**: 处理根证书和设备证书
4. **无私钥文件**: 客户端不需要加载私钥文件
5. **TPM2兼容**: 参考TPM2 Provider设计

## 编译依赖

- OpenSSL 3.0.9
- GCC 或 Clang
- Make
- Ubuntu 18.04+

## 快速开始

1. 编译Provider:
```bash
make all
```

2. 生成测试证书:
```bash
cd certs && ./generate_certs.sh
```

3. 运行测试:
```bash
make test
```

4. 运行客户端/服务端示例:
```bash
# 终端1 - 启动服务端
./build/server

# 终端2 - 启动客户端
./build/client
```

## 技术原理

### 1. Provider机制
OpenSSL 3.0引入了Provider机制，允许动态加载算法实现。本项目通过实现以下接口：
- 密钥管理接口
- 签名算法接口
- 加密算法接口
- 证书存储接口

### 2. TEE集成
通过TEE接口抽象层，将密钥操作委托给TEE环境：
- 私钥永不离开TEE
- 签名操作在TEE内完成
- 证书验证通过TEE接口

### 3. 证书链处理
支持多级证书链：
- 根证书
- 中间证书
- 设备证书

## 配置说明

Provider配置文件 `config/provider.conf`:
```ini
[tee_provider]
module = ./build/libtee_provider.so
activate = 1
default_algorithms = RSA:EC:SHA256:AES
```

## 注意事项

1. 确保OpenSSL版本为3.0.9
2. TEE接口需要根据实际硬件环境调整
3. 证书路径需要根据实际部署环境修改
4. 建议在生产环境中启用更严格的安全检查