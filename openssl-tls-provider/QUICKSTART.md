# 快速使用指南

本指南帮助您快速上手OpenSSL TLS Provider项目。

## 前提条件

确保您的系统满足以下要求：

- Ubuntu 20.04+ 或其他Linux发行版
- OpenSSL 3.0.9 安装在 `/opt/openssl-3.0.9/dist`
- GCC编译器和make工具

## 5分钟快速开始

### 1. 检查环境

```bash
cd openssl-tls-provider

# 检查OpenSSL是否正确安装
/opt/openssl-3.0.9/dist/bin/openssl version

# 应该显示：OpenSSL 3.0.9 xxx
```

### 2. 一键构建和测试

```bash
# 执行完整构建流程
./scripts/build.sh all
```

这个命令会自动：
- 检查编译环境
- 生成测试证书
- 编译所有组件
- 运行测试

### 3. 手动测试

如果需要手动测试，可以：

```bash
# 终端1: 启动服务器
./build/tls_server

# 终端2: 运行客户端
./build/tls_client
```

## 详细步骤

### 步骤1: 环境检查

```bash
./scripts/build.sh check
```

如果检查失败，请确保：
- OpenSSL 3.0.9 正确安装
- 库文件路径正确设置
- 编译环境完整

### 步骤2: 生成证书

```bash
./scripts/build.sh certs
```

这会在`certs/`目录下生成：
- CA证书和私钥
- 服务器证书和私钥
- 客户端证书和私钥

### 步骤3: 编译项目

```bash
./scripts/build.sh build
```

编译完成后，`build/`目录会包含：
- `libtee_provider.so` - TEE Provider库
- `tls_client` - TLS客户端
- `tls_server` - TLS服务器

### 步骤4: 运行测试

```bash
./scripts/build.sh test
```

测试会自动：
- 启动TLS服务器
- 运行客户端连接测试
- 验证TLS握手成功
- 停止服务器

## 使用Makefile

您也可以使用Makefile进行构建：

```bash
# 检查环境
make check-env

# 生成证书
make certs

# 编译所有组件
make all

# 运行测试
make test

# 清理构建文件
make clean
```

## 自定义配置

### 修改OpenSSL路径

如果您的OpenSSL安装在不同位置，请修改：

1. **Makefile中的配置**：
   ```makefile
   OPENSSL_PREFIX = /your/openssl/path
   ```

2. **构建脚本中的配置**：
   ```bash
   OPENSSL_PREFIX="/your/openssl/path"
   ```

### 修改服务器端口

```bash
# 使用不同端口启动服务器
./build/tls_server -p 8443

# 客户端连接到不同端口
./build/tls_client -h 127.0.0.1 -p 8443
```

## 常见问题解决

### 问题1: OpenSSL版本不匹配

```bash
# 检查版本
/opt/openssl-3.0.9/dist/bin/openssl version

# 如果版本不正确，请重新安装OpenSSL 3.0.9
```

### 问题2: 库文件找不到

```bash
# 设置库路径
export LD_LIBRARY_PATH=/opt/openssl-3.0.9/dist/lib64:/opt/openssl-3.0.9/dist/lib:$LD_LIBRARY_PATH

# 重新运行
./build/tls_client
```

### 问题3: 权限问题

```bash
# 确保脚本有执行权限
chmod +x scripts/build.sh scripts/generate_certs.sh
```

### 问题4: 端口占用

```bash
# 检查端口占用
netstat -tlnp | grep 4433

# 使用其他端口
./build/tls_server -p 8443
```

## 验证成功

如果一切正常，您应该看到：

```
=== 基于TEE Provider的TLS客户端 ===
连接目标: 127.0.0.1:4433
[INFO] 开始加载TEE Provider
[TEE Provider] TEE Provider 初始化开始
[TEE Provider] TEE Provider 初始化完成
[INFO] TEE Provider加载成功
[INFO] 创建SSL上下文
[INFO] 配置使用TEE Provider进行私钥操作
[INFO] TCP连接建立成功
[INFO] 开始TLS握手
[TEE Provider] 签名上下文创建成功
[TEE Provider] 私钥加载成功（模拟TEE环境）
[TEE Provider] 签名初始化成功
[TEE Provider] 执行TEE签名操作
[TEE Provider] TEE签名操作成功
[INFO] TLS握手成功
[INFO] 连接信息:
协议版本: TLSv1.3
密码套件: TLS_AES_256_GCM_SHA384
```

## 下一步

- 查看[README.md](README.md)了解详细实现原理
- 修改代码以适应您的具体需求
- 集成到您的项目中

## 支持

如果遇到问题，请：

1. 检查[故障排除](#常见问题解决)部分
2. 查看详细的[README.md](README.md)
3. 提交Issue或寻求帮助

---

**祝您使用愉快！**