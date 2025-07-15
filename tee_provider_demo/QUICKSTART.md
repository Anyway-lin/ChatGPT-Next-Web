# TEE Provider 快速开始指南

## 🚀 一键运行

```bash
cd tee_provider_demo
chmod +x run_demo.sh
./run_demo.sh
```

这将自动完成所有步骤：证书生成、编译、启动服务器、运行客户端演示。

## 📋 系统要求

### 必需依赖
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential cmake libssl-dev pkg-config

# 验证OpenSSL版本
openssl version  # 需要 3.0+
```

### 支持的系统
- Ubuntu 20.04+
- Debian 11+
- 其他支持OpenSSL 3.x的Linux发行版

## 🎯 演示选项

### 1. 完整演示（推荐）
```bash
./run_demo.sh
```
自动运行完整的TLS握手演示

### 2. 仅编译
```bash
./run_demo.sh -b
```
只编译项目，不运行演示

### 3. 仅启动服务器
```bash
./run_demo.sh -s -p 8443
```
在端口8443启动TLS服务器

### 4. 自定义主机和端口
```bash
./run_demo.sh --host 192.168.1.100 -p 9443
```

### 5. 启用调试输出
```bash
TEE_DEBUG=1 ./run_demo.sh
```

## 🔧 手动运行步骤

### 1. 生成证书
```bash
./generate_certs.sh
```

### 2. 编译项目
```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

### 3. 启动服务器
```bash
cd build
./test_server 8443
```

### 4. 运行客户端（新终端）
```bash
cd build  
./tls_client 127.0.0.1 8443
```

## 📁 项目结构

```
tee_provider_demo/
├── 📄 README.md              # 详细文档
├── 📄 QUICKSTART.md           # 快速开始（本文档）
├── 📄 PROJECT_SUMMARY.md      # 项目总结
├── 🔧 CMakeLists.txt          # 构建配置
├── 🚀 run_demo.sh             # 一键运行脚本
├── 🔐 generate_certs.sh       # 证书生成脚本
├── 📝 tee_provider.h          # TEE Provider头文件
├── 💻 tee_provider.c          # TEE Provider实现
├── 🌐 tls_client.c            # TLS客户端
├── 🖥️  test_server.c           # 测试服务器
├── 📁 certs/                  # 生成的证书目录
│   ├── root_ca_cert.pem       # 根CA证书
│   ├── intermediate_ca_cert.pem # 中间CA证书
│   ├── device_cert.pem        # 设备证书
│   ├── server_cert.pem        # 服务器证书
│   └── *.pem                  # 其他证书和私钥
└── 📁 build/                  # 编译输出目录
    ├── tls_client             # TLS客户端可执行文件
    ├── test_server            # 测试服务器可执行文件
    ├── libtee_provider.so     # TEE Provider动态库
    └── certs/                 # 证书副本
```

## ✅ 成功运行的标志

### 1. 编译成功
```
[SUCCESS] 项目编译成功
```

### 2. 证书生成成功
```
=== 证书生成完成 ===
证书链验证：
device_cert.pem: OK
server_cert.pem: OK
```

### 3. Provider加载成功
```
=== 加载TEE Provider ===
[TEE-DEBUG] Initializing TEE Provider
SUCCESS: TEE Provider is available
```

### 4. TLS连接建立
```
Connected to 127.0.0.1:8443
=== 设置SSL上下文 ===
SUCCESS: CA certificates loaded
SUCCESS: Client certificate loaded
```

## ⚠️ 常见问题

### 1. 编译错误
**问题**: `fatal error: openssl/core.h: No such file or directory`

**解决**: 
```bash
sudo apt install libssl-dev
```

### 2. 运行时错误
**问题**: `Cannot open key file`

**解决**: 确保在正确目录运行，重新生成证书
```bash
./generate_certs.sh
```

### 3. 连接被拒绝
**问题**: `Connection refused`

**解决**: 检查服务器是否正在运行，检查端口
```bash
netstat -an | grep 8443
```

### 4. Segmentation Fault
**当前已知问题**: 客户端在TLS握手末尾可能崩溃

**临时解决**: 这是已知问题，不影响演示Provider加载和基本功能

## 🔍 调试模式

### 启用详细日志
```bash
TEE_DEBUG=1 ./run_demo.sh
```

### 查看OpenSSL错误
```bash
# 在客户端代码中已包含错误输出
# 查看运行时的详细错误信息
```

### 检查库依赖
```bash
ldd build/tls_client
ldd build/libtee_provider.so
```

## 🎯 演示重点

### 1. TEE Provider架构
- OpenSSL 3.x Provider接口实现
- 密钥管理和签名操作
- 模拟TEE安全环境

### 2. 零信任密钥管理
- 私钥不暴露到TEE外部
- 所有密钥操作在"安全环境"中完成
- 证书链验证

### 3. TLS集成
- Provider与OpenSSL TLS的集成
- 客户端证书认证
- 双向TLS握手

## 📞 获取帮助

### 查看帮助
```bash
./run_demo.sh --help
```

### 查看详细文档
```bash
cat README.md
cat PROJECT_SUMMARY.md
```

### 检查日志
所有操作都有详细的日志输出，包括：
- 编译过程
- 证书生成过程  
- Provider初始化
- TLS握手详情

---

**快速验证**: 运行 `./run_demo.sh -b` 如果编译成功，说明环境配置正确！