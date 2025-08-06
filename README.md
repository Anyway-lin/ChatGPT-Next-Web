# Android TEE TLS客户端

## 概述

本项目实现了Android Java环境下使用OkHttp通过TEE（Trusted Execution Environment，可信执行环境）进行无私钥TLS握手的解决方案。私钥安全存储在TEE中，签名操作通过TEE接口完成，确保私钥永不暴露到普通应用环境。

## 特性

- ✅ **无私钥暴露**: 私钥始终保存在TEE中，应用层无法访问
- ✅ **TEE签名**: 所有签名操作通过TEE接口完成
- ✅ **OkHttp集成**: 完美集成OkHttp客户端
- ✅ **TLS 1.2/1.3支持**: 支持现代TLS协议
- ✅ **多算法支持**: 支持RSA和ECDSA签名算法
- ✅ **错误处理**: 完善的错误处理和重试机制
- ✅ **生产就绪**: 可用于生产环境的完整实现

## 架构

```
应用层
    ↓
TeeOkHttpClient (OkHttp集成)
    ↓
TeeSSLContextManager (SSL上下文管理)
    ↓
TeeX509KeyManager (密钥管理器)
    ↓
TeeSignatureProvider (签名提供者)
    ↓
TeeSignatureInterface (TEE接口)
    ↓
TEE硬件/固件
```

## 核心组件

### 1. TeeSignatureInterface
TEE签名接口定义，封装了TEE的签名操作：
```java
public interface TeeSignatureInterface {
    byte[] sign(byte[] data, String algorithm) throws Exception;
    X509Certificate[] getCertificateChain() throws Exception;
    String[] getSupportedAlgorithms();
    boolean isAvailable();
}
```

### 2. TeeX509KeyManager
自定义密钥管理器，不暴露私钥，所有签名操作委托给TEE：
```java
@Override
public PrivateKey getPrivateKey(String alias) {
    return new TeePrivateKey(teeInterface); // 代理私钥
}
```

### 3. TeeSignatureProvider
自定义签名提供者，将Java标准签名操作重定向到TEE：
```java
@Override
protected byte[] engineSign() throws SignatureException {
    return teeInterface.sign(dataToSign, algorithm);
}
```

### 4. TeeOkHttpClient
完整的OkHttp客户端封装，提供简单易用的API：
```java
TeeOkHttpClient client = new TeeOkHttpClient(teeInterface, true);
client.buildClient(false);
Response response = client.get("https://example.com");
```

## 使用方法

### 基本用法

```java
// 1. 创建TEE接口实例
TeeSignatureInterface teeInterface = new YourTeeImplementation();

// 2. 创建TEE客户端
TeeOkHttpClient teeClient = new TeeOkHttpClient(teeInterface, true);

// 3. 构建客户端
teeClient.buildClient(false); // false = 生产环境，验证证书

// 4. 执行HTTPS请求
try (Response response = teeClient.get("https://api.example.com/data")) {
    System.out.println("Response: " + response.body().string());
}

// 5. 清理资源
teeClient.cleanup();
```

### 高级用法

```java
// POST请求
String json = "{\"key\": \"value\"}";
RequestBody body = RequestBody.create(json, MediaType.get("application/json"));
Response response = teeClient.post("https://api.example.com/submit", body);

// 使用原始OkHttp客户端
OkHttpClient rawClient = teeClient.getClient();
Request request = new Request.Builder()
    .url("https://example.com")
    .addHeader("Authorization", "Bearer token")
    .build();
Response response = rawClient.newCall(request).execute();
```

## TEE接口实现

在实际项目中，您需要实现真实的TEE接口。以下是一个典型的实现框架：

```java
public class RealTeeSignatureImpl implements TeeSignatureInterface {
    
    private native byte[] nativeSign(byte[] data, String algorithm);
    private native byte[][] nativeGetCertificateChain();
    private native boolean nativeIsAvailable();
    
    static {
        System.loadLibrary("tee_signature"); // 加载JNI库
    }
    
    @Override
    public byte[] sign(byte[] data, String algorithm) throws Exception {
        if (!isAvailable()) {
            throw new IllegalStateException("TEE not available");
        }
        return nativeSign(data, algorithm);
    }
    
    @Override
    public X509Certificate[] getCertificateChain() throws Exception {
        byte[][] certBytes = nativeGetCertificateChain();
        X509Certificate[] certs = new X509Certificate[certBytes.length];
        
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        for (int i = 0; i < certBytes.length; i++) {
            certs[i] = (X509Certificate) factory.generateCertificate(
                new ByteArrayInputStream(certBytes[i]));
        }
        
        return certs;
    }
    
    @Override
    public boolean isAvailable() {
        return nativeIsAvailable();
    }
    
    @Override
    public String[] getSupportedAlgorithms() {
        return new String[]{"SHA256withRSA", "SHA256withECDSA"};
    }
}
```

## Android集成

### 1. 添加依赖

在`build.gradle`中添加：
```gradle
implementation 'com.squareup.okhttp3:okhttp:4.12.0'
implementation 'com.squareup.okhttp3:logging-interceptor:4.12.0'
implementation 'org.bouncycastle:bcprov-jdk15on:1.70'
```

### 2. 权限配置

在`AndroidManifest.xml`中添加：
```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

### 3. 网络安全配置

创建`network_security_config.xml`：
```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">your-secure-domain.com</domain>
    </domain-config>
</network-security-config>
```

## 安全考虑

### 1. 证书验证
- 生产环境中始终使用`buildClient(false)`验证服务器证书
- 考虑证书固定（Certificate Pinning）以防止中间人攻击

### 2. TEE安全
- 确保TEE实现符合安全标准（如ARM TrustZone、Intel SGX）
- 定期更新TEE固件和密钥材料

### 3. 网络安全
- 使用最新的TLS版本（推荐TLS 1.3）
- 配置强加密套件
- 实施HSTS（HTTP Strict Transport Security）

## 测试

运行示例代码：
```bash
javac -cp ".:lib/*" *.java
java -cp ".:lib/*" com.example.tls.demo.TeeHttpsExample
```

## 故障排除

### 常见问题

1. **TEE不可用**
   ```
   错误: TEE is not available
   解决: 检查设备是否支持TEE，验证TEE服务是否正常运行
   ```

2. **证书链错误**
   ```
   错误: Certificate chain validation failed
   解决: 检查证书格式和有效期，确保证书链完整
   ```

3. **签名失败**
   ```
   错误: TEE signing failed
   解决: 检查TEE密钥状态，验证签名算法支持
   ```

### 调试技巧

1. 启用详细日志：
```java
TeeOkHttpClient client = new TeeOkHttpClient(teeInterface, true);
```

2. 检查TEE状态：
```java
if (!client.isTeeAvailable()) {
    Log.e("TEE", "TEE not available");
}
```

3. 验证支持的算法：
```java
String[] algorithms = client.getSupportedAlgorithms();
Log.d("TEE", "Supported algorithms: " + Arrays.toString(algorithms));
```

## 贡献

欢迎提交Issue和Pull Request来改进项目。

## 许可证

本项目采用MIT许可证。详见LICENSE文件。

## 联系方式

如有问题，请通过GitHub Issues联系。
