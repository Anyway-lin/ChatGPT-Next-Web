# OpenSSL TLS Provider 项目

基于OpenSSL 3.0.9的TEE Provider模型实现，模拟TEE环境中的私钥操作和TLS握手。

## 项目概述

本项目实现了一个自定义的OpenSSL Provider，模拟TEE（Trusted Execution Environment）环境中的私钥操作。虽然没有真实的TEE环境，但通过自定义Provider的方式，实现了私钥操作的安全封装，确保私钥不会直接暴露给应用程序。

## 功能特性

- 🔐 **自定义TEE Provider**: 实现OpenSSL 3.0.9的Provider模型
- 🛡️ **私钥安全**: 模拟TEE环境中的私钥操作
- 🤝 **TLS握手**: 完整的客户端/服务器TLS握手实现
- 📜 **证书管理**: 自动生成测试证书
- 🧪 **完整测试**: 提供完整的测试框架

## 项目结构

```
openssl-tls-provider/
├── src/                    # 源代码目录
│   ├── tee_provider.c      # TEE Provider实现
│   ├── tee_provider.h      # TEE Provider头文件
│   ├── tls_client.c        # TLS客户端实现
│   └── tls_server.c        # TLS服务器实现
├── scripts/                # 脚本目录
│   ├── generate_certs.sh   # 证书生成脚本
│   └── build.sh           # 构建脚本
├── certs/                  # 证书目录（运行时生成）
├── build/                  # 构建输出目录
├── Makefile               # 构建文件
└── README.md              # 项目说明
```

## 环境要求

### 必要条件

- **操作系统**: Ubuntu 20.04+ 或其他Linux发行版
- **OpenSSL**: 3.0.9版本，安装在`/opt/openssl-3.0.9/dist`
- **编译器**: GCC 8.0+
- **构建工具**: make

### 安装依赖

```bash
# 安装基础编译环境
sudo apt-get update
sudo apt-get install gcc make build-essential

# 安装OpenSSL开发库（如果系统OpenSSL版本不匹配）
sudo apt-get install libssl-dev
```

## 快速开始

### 1. 克隆项目

```bash
git clone <repository-url>
cd openssl-tls-provider
```

### 2. 检查环境

```bash
# 使用构建脚本检查环境
./scripts/build.sh check

# 或使用Makefile
make check-env
```

### 3. 生成证书

```bash
# 生成测试证书
./scripts/build.sh certs

# 或使用Makefile
make certs
```

### 4. 编译项目

```bash
# 编译所有组件
./scripts/build.sh build

# 或使用Makefile
make all
```

### 5. 运行测试

```bash
# 运行完整测试
./scripts/build.sh test

# 或使用Makefile
make test
```

### 6. 一键构建

```bash
# 执行完整构建流程（检查环境 + 生成证书 + 编译 + 测试）
./scripts/build.sh all
```

## 详细使用说明

### 证书生成

项目会自动生成以下证书：

- `certs/ca.pem` - CA根证书
- `certs/ca.key` - CA私钥
- `certs/server.pem` - 服务器证书
- `certs/server.key` - 服务器私钥
- `certs/client.pem` - 客户端证书
- `certs/client.key` - 客户端私钥

### 编译组件

项目包含三个主要组件：

1. **TEE Provider库** (`build/libtee_provider.so`)
   - 实现OpenSSL 3.0.9的Provider接口
   - 模拟TEE环境中的私钥操作

2. **TLS客户端** (`build/tls_client`)
   - 使用TEE Provider进行TLS握手
   - 支持双向认证

3. **TLS服务器** (`build/tls_server`)
   - 标准TLS服务器实现
   - 用于测试客户端连接

### 手动运行

#### 启动TLS服务器

```bash
# 启动服务器（默认端口4433）
./build/tls_server

# 指定端口
./build/tls_server -p 8443

# 查看帮助
./build/tls_server --help
```

#### 运行TLS客户端

```bash
# 连接到本地服务器
./build/tls_client

# 连接到指定服务器
./build/tls_client -h 192.168.1.100 -p 8443

# 查看帮助
./build/tls_client --help
```

## 实现原理

### TEE Provider模型

OpenSSL 3.0.9引入了Provider模型，允许开发者自定义加密操作的实现。本项目实现了一个TEE Provider，包含以下核心功能：

1. **Provider初始化**
   - 注册Provider到OpenSSL框架
   - 设置算法查询函数

2. **签名操作**
   - 实现RSA签名算法
   - 模拟TEE环境中的私钥操作

3. **安全封装**
   - 私钥操作封装在Provider内部
   - 应用程序无法直接访问私钥

### TLS握手流程

1. **客户端初始化**
   - 加载TEE Provider
   - 设置私钥路径
   - 创建SSL上下文

2. **握手过程**
   - TCP连接建立
   - TLS握手协商
   - 证书验证
   - 密钥交换

3. **数据传输**
   - 加密数据传输
   - 完整性验证

### 关键特性

- **私钥隔离**: 私钥操作在Provider内部完成
- **透明集成**: 对应用程序透明的安全增强
- **灵活配置**: 支持不同的证书和密钥配置
- **完整日志**: 详细的操作日志记录

## 配置选项

### 环境变量

```bash
# 设置OpenSSL路径
export OPENSSL_PREFIX=/opt/openssl-3.0.9/dist

# 设置库路径
export LD_LIBRARY_PATH=$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib:$LD_LIBRARY_PATH
```

### 编译选项

可以通过修改`Makefile`中的配置来调整编译选项：

```makefile
# 修改OpenSSL路径
OPENSSL_PREFIX = /your/openssl/path

# 修改编译选项
CFLAGS = -Wall -Wextra -g -O2 -fPIC

# 修改链接选项
LDFLAGS = -L$(OPENSSL_PREFIX)/lib64 -L$(OPENSSL_PREFIX)/lib
```

## 故障排除

### 常见问题

1. **OpenSSL版本不匹配**
   ```bash
   # 检查OpenSSL版本
   /opt/openssl-3.0.9/dist/bin/openssl version
   
   # 确保版本为3.0.9
   ```

2. **库文件找不到**
   ```bash
   # 设置库路径
   export LD_LIBRARY_PATH=/opt/openssl-3.0.9/dist/lib64:/opt/openssl-3.0.9/dist/lib:$LD_LIBRARY_PATH
   ```

3. **证书验证失败**
   ```bash
   # 重新生成证书
   make clean-certs
   make certs
   ```

4. **端口占用**
   ```bash
   # 检查端口占用
   netstat -tlnp | grep 4433
   
   # 使用不同端口
   ./build/tls_server -p 8443
   ./build/tls_client -h 127.0.0.1 -p 8443
   ```

### 调试方法

1. **启用详细日志**
   ```bash
   # 客户端详细模式
   ./build/tls_client -v
   ```

2. **查看Provider状态**
   ```bash
   # 检查Provider是否正确加载
   /opt/openssl-3.0.9/dist/bin/openssl list -providers
   ```

3. **验证证书链**
   ```bash
   # 验证证书
   /opt/openssl-3.0.9/dist/bin/openssl verify -CAfile certs/ca.pem certs/client.pem
   ```

## 安全说明

本项目仅用于学习和测试目的，不建议在生产环境中使用。主要安全考虑：

1. **测试证书**: 使用自签名证书，不适用于生产环境
2. **简化实现**: Provider实现相对简化，缺少完整的安全检查
3. **密钥管理**: 私钥仍存储在文件系统中，未实现真正的TEE保护

## 许可证

本项目基于MIT许可证发布。

## 贡献指南

欢迎提交问题报告和功能请求。如需贡献代码，请：

1. Fork项目
2. 创建功能分支
3. 提交更改
4. 发起Pull Request

## 支持

如有问题或建议，请通过以下方式联系：

- 提交Issue
- 发送邮件
- 技术讨论

---

**注意**: 本项目仅用于教育和研究目的，不建议在生产环境中使用。