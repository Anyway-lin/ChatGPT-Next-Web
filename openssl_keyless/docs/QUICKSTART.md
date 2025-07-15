# 🚀 OpenSSL Keyless 快速启动指南

本指南将帮您在5分钟内运行完整的keyless TLS演示。

## 📋 前提条件

确保系统已安装必要依赖：

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential libssl-dev pkg-config

# CentOS/RHEL
sudo yum install gcc openssl-devel pkgconfig

# macOS
brew install openssl pkg-config
```

## 🏗️ 快速构建

```bash
# 1. 进入项目目录
cd openssl_keyless

# 2. 构建所有组件
make all

# 3. 验证构建结果
ls build/
```

预期输出：
```
build/keyless_tls_server    # TLS服务器
build/simple_client         # TLS客户端  
build/keyless_demo          # 完整演示
build/libkeyless.so         # 共享库
build/libkeyless.a          # 静态库
```

## 🎭 运行演示

### 方式一：完整演示（单进程）

```bash
make run-demo
```

这将运行一个完整的keyless TLS演示，展示：
- TEE环境初始化
- Keyless私钥创建
- TLS握手过程
- 签名操作重定向

### 方式二：服务器-客户端模式

**终端1：启动服务器**
```bash
make run-server
```

预期输出：
```
🔐 === Keyless TLS Server Initialization ===

1. Initializing TEE environment...
✅ TEE initialized successfully

2. Creating TEE keyless private key (ID: 100)...
✅ TEE keyless private key created

3. Creating certificate keypair...
✅ Certificate keypair created

4. Creating server certificate for localhost...
✅ Server certificate created

5. Starting TLS server...
🚀 Starting Keyless TLS Server on port 8443...
✅ Keyless TLS Server listening on localhost:8443
🔑 Private key secured in TEE environment
📜 Certificate configured with SAN: localhost, localhost, 127.0.0.1

💡 Available commands for clients:
   - Send any message for echo
   - 'STATUS' to get server status
   - 'SIGN:data' to test TEE signing
   - 'QUIT' to close connection

🛑 Press Ctrl+C to stop server
```

**终端2：启动客户端**
```bash
make run-client
```

预期输出：
```
🔗 === Simple TLS Client ===

🔗 Connecting to 127.0.0.1:8443...
✅ Connected to server
🤝 Performing TLS handshake...
✅ TLS handshake completed!
   Protocol: TLSv1.3
   Cipher: TLS_AES_256_GCM_SHA384
   Server certificate: /C=CN/ST=Beijing/L=Beijing/O=Keyless TLS Server/OU=Security Department/CN=localhost

💬 Interactive mode started. Type messages to send to server.
   Special commands: STATUS, SIGN:data, QUIT
   Press Ctrl+C to exit

📝 Enter message: 
```

## 🤝 交互式测试

在客户端中，您可以尝试以下命令：

### 1. 检查服务器状态
```
📝 Enter message: STATUS
📨 Server response:
🔐 Keyless TLS Server Status:
  Protocol: TLSv1.3
  Cipher: TLS_AES_256_GCM_SHA384
  TEE Handle: Active
  Private Key: Secured in TEE
  Connection: Active
```

### 2. 测试TEE签名
```
📝 Enter message: SIGN:Hello Keyless World!
📨 Server response:
🔑 TEE Signature completed: 256 bytes
✅ Data signed securely in TEE environment
```

### 3. 回显测试
```
📝 Enter message: 测试中文消息
📨 Server response:
🔐 Keyless TLS Server Echo: 测试中文消息
```

### 4. 优雅退出
```
📝 Enter message: quit
📨 Server response:
Goodbye! Connection closed by client request.
✅ Connection closed gracefully
```

## 🧪 运行测试套件

验证所有功能正常工作：

```bash
make test
```

预期输出：
```
🧪 Running All Tests...
======================
🔬 Running build/test_keyless...
🔐 === Comprehensive Keyless SSL Test Suite ===
✅ TEE initialization test passed
✅ TEE key creation test passed  
✅ TEE signing test passed
✅ Keyless SSL integration test passed
✅ All tests completed successfully!

🔬 Running build/debug_test...
🔍 === Debug Test Suite ===
✅ Debug tests passed

✅ All tests completed successfully!
```

## 🎯 核心特性验证

### ✅ Keyless机制验证

1. **私钥隔离**：私钥永不离开TEE环境
2. **签名重定向**：OpenSSL签名操作自动重定向到TEE
3. **TLS兼容**：完整支持标准TLS/SSL协议
4. **透明集成**：对现有应用零修改

### ✅ 安全特性验证

- 🔐 私钥在内存中无明文存储
- 🛡️ TEE提供硬件级安全保护
- ✅ 签名结果通过OpenSSL验证
- 🔒 支持现代TLS协议（TLS 1.2/1.3）

## 🔧 自定义配置

### 修改服务器端口
```bash
make run-server PORT=9443
# 或
./build/keyless_tls_server -p 9443
```

### 连接远程服务器
```bash
./build/simple_client -s 192.168.1.100 -p 9443
```

### 使用不同的TEE密钥ID
```bash
./build/keyless_tls_server -k 200
```

## 🐛 故障排除

### 1. 构建失败
```bash
# 检查依赖
make check-deps

# 重新构建
make clean && make all
```

### 2. 连接失败
```bash
# 检查端口是否被占用
netstat -tlnp | grep 8443

# 检查防火墙设置
sudo ufw status
```

### 3. TLS握手失败
```bash
# 启用SSL调试
export OPENSSL_DEBUG=1
make run-client
```

### 4. 内存泄漏检查
```bash
# 使用Valgrind检查
make valgrind-demo
make valgrind-server
```

## 📊 性能基准

运行性能测试：
```bash
make benchmark
```

典型性能指标：
- RSA-2048签名：~1ms
- ECDSA-P256签名：~0.5ms
- TLS握手：~10ms
- 内存使用：<1MB

## 🎊 成功标志

如果您看到以下输出，说明keyless机制工作正常：

```
🎉 TLS handshake completed successfully!
Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
✅ Keyless mechanism demonstrated
✅ TEE integration working  
✅ Private key isolation achieved
✅ Secure communication established
```

## 📚 下一步

- 阅读 [API文档](API.md) 了解详细接口
- 查看 [架构设计](ARCHITECTURE.md) 理解实现原理
- 参考 [示例代码](../examples/) 进行定制开发

## 💡 快速命令参考

```bash
# 构建
make all                    # 构建所有组件
make clean                  # 清理构建文件

# 运行
make run-server            # 启动服务器
make run-client            # 启动客户端
make run-demo              # 运行完整演示

# 测试
make test                  # 运行测试套件
make valgrind-demo         # 内存检查
make benchmark             # 性能测试

# 开发
make format                # 代码格式化
make static-analysis       # 静态分析
make help                  # 显示所有命令
```

🎯 **目标达成**：您现在已经成功运行了完整的OpenSSL keyless机制演示！

---

*遇到问题？查看 [FAQ](FAQ.md) 或提交Issue。*