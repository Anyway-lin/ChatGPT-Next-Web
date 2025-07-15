# 快速开始指南

## 一键运行

```bash
# 进入项目目录
cd openssl-provider-tls

# 安装依赖（需要sudo权限）
sudo ./install_deps.sh

# 编译和运行演示
make all && make certs

# 启动服务器（保持运行）
make test-server &

# 等待2秒让服务器启动
sleep 2

# 运行客户端测试
make test-client

# 停止服务器
pkill tls_server
```

## 手动运行

### 步骤1：安装依赖
```bash
sudo ./install_deps.sh
```

### 步骤2：编译项目
```bash
make all
```

### 步骤3：生成证书
```bash
make certs
```

### 步骤4：测试（两个终端）

**终端1（服务器）：**
```bash
make test-server
```

**终端2（客户端）：**
```bash
make test-client
```

## 预期输出

### 成功的客户端输出：
```
=== TLS客户端启动（简化版本） ===
=== 初始化TEE Provider ===
TEE Provider: 私钥加载成功
TEE Provider: ✓ 签名验证测试成功！
=== 建立TLS连接 ===
✓ TLS握手成功！
TLS版本: TLSv1.3
加密套件: TLS_AES_256_GCM_SHA384
=== 数据传输测试 ===
发送成功，字节数: 52
接收数据: Hello from TLS Server! Your TEE Provider works perfectly!
✓ TLS客户端测试成功完成！
```

### 成功的服务器输出：
```
=== TLS服务器启动 ===
=== 服务器就绪，等待客户端连接 ===
=== 处理新的客户端连接 ===
✓ TLS握手成功！
客户端证书验证: ✓ 验证成功
接收到客户端数据 (52字节)
发送响应 (57字节)
```

## 故障排除

### 常见问题

1. **编译错误：头文件找不到**
   ```bash
   # 安装OpenSSL开发包
   sudo apt-get install libssl-dev
   ```

2. **权限问题**
   ```bash
   # 确保脚本有执行权限
   chmod +x *.sh scripts/*.sh
   ```

3. **端口占用**
   ```bash
   # 检查端口8443是否被占用
   netstat -tulpn | grep 8443
   
   # 如果被占用，停止相关进程或使用其他端口
   ```

4. **证书问题**
   ```bash
   # 重新生成证书
   make clean-certs && make certs
   ```

### 验证安装

```bash
# 检查编译结果
ls -la build/
# 应该看到：tls_client_simple, tls_server

# 检查证书
ls -la certs/
# 应该看到各种.pem文件

# 检查环境
make check-env
```

## 文件说明

- `tls_client_simple` - TEE Provider TLS客户端
- `tls_server` - 标准TLS服务器
- `certs/device-key-nopass.pem` - 设备私钥（TEE Provider使用）
- `certs/device-chain.pem` - 设备证书链
- `certs/ca-cert.pem` - 根CA证书

## 技术要点

1. **TEE Provider**: 私钥操作在Provider内部完成
2. **双向认证**: 客户端和服务器互相验证证书
3. **TLS 1.3**: 使用最新的TLS协议
4. **证书链**: 支持完整的证书信任链验证

---

如有问题，请查看 `PROJECT_SUMMARY.md` 或 `README.md` 获取更详细信息。