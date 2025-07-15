# TEE Provider V2 关键修复指南

## 🔧 已修复的关键问题

### 问题1: "missing private key" 错误
**症状**: `error:020000B3:rsa routines::missing private key`

**根本原因**: 
- `tee_keymgmt_export_types` 函数没有声明支持私钥参数类型
- `tee_keymgmt_export` 函数在处理私钥选择时提供的信息不足

**修复方案**:
1. **修复 `tee_keymgmt_export_types`**: 当OpenSSL查询私钥参数类型支持时，我们现在正确声明支持 `OSSL_PKEY_PARAM_RSA_D` 参数类型
2. **增强 `tee_keymgmt_export`**: 当OpenSSL请求导出私钥时，我们提供足够的公钥参数让OpenSSL确认密钥的完整性
3. **改进 `tee_keymgmt_has`**: 更好地处理组合选择查询

### 问题2: 密钥匹配失败
**症状**: `key values mismatch`

**根本原因**: 
- 密钥匹配逻辑过于严格
- 未正确处理TEE密钥与标准密钥的比较

**修复方案**:
- 实现了宽松但安全的密钥匹配机制
- 正确处理一个密钥为TEE密钥，另一个为标准密钥的情况

## 🚀 使用指南

### 1. 重新编译
```bash
cd openssl-tls-provider
make clean && make
```

### 2. 测试基本功能
```bash
# 测试TEE Provider加载
./build/test_tee_v2_simple

# 测试密钥导出功能
./build/test_key_export
```

### 3. 启动TLS服务器
```bash
# 在一个终端中启动服务器
./build/tls_server
```

### 4. 测试TEE TLS客户端
```bash
# 在另一个终端中运行客户端
./build/tls_client_v2
```

## 🔍 预期的日志输出

### 成功的关键指标
```
[TEE-V2] ✅ 声明支持私钥参数类型（虽然私钥在TEE中保护）
[TEE-V2] ✅ 提供公钥参数（私钥在TEE中安全保护）
[TEE-V2] ✅ 密钥ID匹配: 相同TEE密钥
[INFO] ✅ 证书和TEE密钥验证通过
[INFO] ✅ SSL上下文创建成功
```

### 如果看到TEE签名函数被调用
```
[TEE-V2] 🚀 签名：TEE签名初始化
[TEE-V2] 🔐 TEE接口：执行签名操作
[TEE-V2] ✅ 签名：TEE签名完成
```

## 🛠️ 故障排除

### 如果仍然出现 "missing private key" 错误

1. **检查 export_types 调用**:
   确保在日志中看到：
   ```
   [TEE-V2] ✅ 声明支持私钥参数类型（虽然私钥在TEE中保护）
   ```

2. **检查 export 调用**:
   确保在日志中看到：
   ```
   [TEE-V2] ✅ 提供公钥参数（私钥在TEE中安全保护）
   ```

3. **验证密钥能力**:
   运行 `./build/test_key_export` 检查密钥签名能力

### 如果TLS握手仍然失败

1. **确认证书文件存在**:
   ```bash
   ls -la certs/
   # 应该看到: ca.pem, client.pem, server.pem, server.key
   ```

2. **检查服务器是否正在运行**:
   ```bash
   netstat -ln | grep 4433
   # 应该看到服务器监听在端口4433
   ```

3. **使用更详细的日志**:
   在代码中的 `tee_log` 函数中添加时间戳和更多调试信息

## 📝 技术说明

### TEE Provider的工作原理

1. **密钥管理**: 
   - 公钥参数存储在Provider中供OpenSSL使用
   - 私钥永远不离开TEE环境
   - 通过密钥ID标识TEE中的私钥

2. **签名过程**:
   - OpenSSL调用我们的 `tee_signature_digest_sign_*` 函数
   - 我们将签名请求转发给TEE接口
   - TEE内部执行实际的签名操作
   - 返回签名结果给OpenSSL

3. **安全保证**:
   - 私钥材料永不暴露
   - 所有私钥操作在TEE内完成
   - 客户端代码无需处理私钥文件

## ✅ 修复确认清单

- [ ] 重新编译成功
- [ ] 基本测试通过
- [ ] 密钥匹配成功
- [ ] SSL上下文创建成功
- [ ] TCP连接建立成功
- [ ] TLS握手成功（如果服务器正常运行）
- [ ] 看到TEE签名函数被调用

---

**注意**: 如果问题持续存在，请提供完整的日志输出以便进一步诊断。