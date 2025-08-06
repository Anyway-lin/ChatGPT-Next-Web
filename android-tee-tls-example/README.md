# Android TEE TLS引擎示例

这个项目演示如何在Android中使用OkHttp实现自定义TLS引擎，其中签名操作通过TEE (Trusted Execution Environment) 接口完成，而不使用私钥文件。

## 项目概述

该示例项目展示了：

1. **TEE密钥管理器 (TEEKeyManager)**: 实现基于Android KeyStore的安全密钥管理
2. **自定义TLS Socket Factory**: 集成TEE密钥管理器的TLS连接工厂
3. **OkHttp集成**: 如何在OkHttp中使用自定义TLS引擎
4. **数字签名**: 使用TEE进行HTTP请求签名
5. **证书管理**: 自签名证书生成和管理

## 关键特性

### 🔐 TEE安全特性
- 私钥在TEE中生成和存储，永不离开安全环境
- 支持硬件安全模块 (StrongBox)
- 签名操作在TEE中完成
- 密钥不可导出

### 🌐 TLS集成
- 自定义SSL Socket Factory
- 支持TLS 1.2/1.3
- 优先使用ECDSA密码套件
- 应用层协议协商 (ALPN)

### 📱 OkHttp增强
- TEE签名拦截器
- 自动添加数字签名头
- 完整的HTTPS请求支持

## 项目结构

```
android-tee-tls-example/
├── src/main/java/com/example/teetls/
│   ├── TEEKeyManager.kt              # TEE密钥管理器
│   ├── CustomTLSSocketFactory.kt     # 自定义TLS Socket Factory
│   ├── TEEOkHttpClient.kt           # 集成TEE的OkHttp客户端
│   ├── AdvancedTEEManager.kt        # 高级TEE操作
│   └── MainActivity.kt              # 示例Activity
├── src/main/res/
│   ├── layout/activity_main.xml     # 主界面布局
│   ├── xml/network_security_config.xml # 网络安全配置
│   └── values/strings.xml           # 字符串资源
├── src/main/AndroidManifest.xml     # Android清单文件
├── build.gradle                     # 构建配置
└── README.md                        # 本文档
```

## 核心组件详解

### 1. TEEKeyManager
负责TEE密钥的生成、管理和签名操作：

```kotlin
class TEEKeyManager : X509KeyManager {
    // 在TEE中生成椭圆曲线密钥对
    private fun generateTEEKey()
    
    // 使用TEE进行签名
    fun signWithTEE(data: ByteArray): ByteArray
    
    // 验证TEE签名
    fun verifyTEESignature(data: ByteArray, signature: ByteArray): Boolean
}
```

### 2. CustomTLSSocketFactory
自定义TLS Socket Factory，集成TEE密钥管理器：

```kotlin
class CustomTLSSocketFactory : SSLSocketFactory() {
    companion object {
        fun create(teeKeyManager: TEEKeyManager): CustomTLSSocketFactory
    }
    
    // 配置SSL Socket参数
    private fun configureSocket(socket: Socket): Socket
}
```

### 3. TEEOkHttpClient
创建集成TEE的OkHttp客户端：

```kotlin
class TEEOkHttpClient {
    companion object {
        fun create(): OkHttpClient {
            // 初始化TEE密钥管理器
            // 创建自定义TLS Socket Factory
            // 配置OkHttp客户端
        }
    }
}
```

## 安全实现细节

### TEE密钥生成
```kotlin
val keyGenParameterSpec = KeyGenParameterSpec.Builder(
    TEE_KEY_ALIAS,
    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setIsStrongBoxBacked(true)  // 使用硬件安全模块
    .setRandomizedEncryptionRequired(false)
    .build()
```

### TLS配置
```kotlin
// 配置支持的协议版本
socket.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")

// 优先选择ECDSA密码套件
val preferredCipherSuites = supportedCipherSuites.filter { 
    it.contains("ECDSA") || it.contains("ECDHE") 
}
```

### 数字签名
```kotlin
// 构建签名数据
val signatureData = "$method|$url|$headers|$bodyHash|$timestamp"

// 使用TEE进行签名
val signature = teeKeyManager.signWithTEE(signatureData.toByteArray())

// 添加签名头
request.addHeader("X-TEE-Signature", signatureBase64)
```

## 使用方法

### 1. 初始化TEE OkHttp客户端
```kotlin
val okHttpClient = TEEOkHttpClient.create()
```

### 2. 发送HTTPS请求
```kotlin
val request = Request.Builder()
    .url("https://example.com/api")
    .build()

okHttpClient.newCall(request).enqueue(callback)
```

### 3. 验证TEE环境
```kotlin
val advancedTEEManager = AdvancedTEEManager()
val teeInfo = advancedTEEManager.verifyTEEEnvironment()
println("TEE可用: ${teeInfo.isAvailable}")
println("StrongBox支持: ${teeInfo.strongBoxSupported}")
```

## 系统要求

- **Android API Level**: 26+ (Android 8.0)
- **硬件要求**: 支持Android KeyStore的设备
- **推荐硬件**: 支持StrongBox的设备 (Android 9.0+)

## 权限要求

```xml
<!-- 网络权限 -->
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

<!-- 硬件安全模块权限 -->
<uses-permission android:name="android.permission.USE_FINGERPRINT" />
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
```

## 安全注意事项

1. **私钥保护**: 私钥永远不会离开TEE环境
2. **证书验证**: 实现自定义证书验证逻辑
3. **网络安全**: 使用网络安全配置限制明文流量
4. **密钥轮换**: 定期轮换密钥以提高安全性
5. **审计日志**: 记录所有密钥操作用于安全审计

## 测试和验证

### 1. TEE功能测试
```kotlin
// 测试密钥生成
val teeKeyManager = TEEKeyManager()

// 测试签名和验证
val testData = "测试数据".toByteArray()
val signature = teeKeyManager.signWithTEE(testData)
val isValid = teeKeyManager.verifyTEESignature(testData, signature)
```

### 2. TLS连接测试
```kotlin
// 测试HTTPS连接
val request = Request.Builder()
    .url("https://httpbin.org/get")
    .build()

okHttpClient.newCall(request).execute()
```

## 故障排除

### 常见问题

1. **StrongBox不支持**: 在不支持StrongBox的设备上，系统会自动回退到TEE
2. **密钥生成失败**: 检查设备是否支持所需的密钥算法
3. **TLS握手失败**: 验证密码套件和协议版本配置
4. **签名验证失败**: 确保签名数据的构建方式一致

### 调试技巧

1. 启用详细日志记录
2. 检查Android KeyStore状态
3. 验证网络安全配置
4. 测试不同的密码套件

## 扩展功能

### 1. 证书管理
- 自签名证书生成
- 证书链验证
- OCSP验证

### 2. 密钥管理
- 密钥轮换策略
- 密钥备份和恢复
- 多密钥支持

### 3. 性能优化
- 批量签名操作
- 连接池管理
- 缓存优化

## 相关文档

- [Android KeyStore系统](https://developer.android.com/training/articles/keystore)
- [OkHttp文档](https://square.github.io/okhttp/)
- [TLS最佳实践](https://developer.android.com/training/articles/security-ssl)
- [Android安全指南](https://developer.android.com/topic/security)

## 许可证

本项目仅供学习和参考使用。在生产环境中使用时，请确保符合相关安全标准和法规要求。

## 贡献

欢迎提交问题报告和功能请求。在生产环境中使用前，请进行充分的安全评估和测试。