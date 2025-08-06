package com.example.tls.demo;

import com.example.tls.okhttp.TeeOkHttpClient;
import com.example.tls.tee.MockTeeSignatureImpl;
import com.example.tls.tee.TeeSignatureInterface;

import okhttp3.MediaType;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.io.IOException;
import java.util.Arrays;

/**
 * TEE HTTPS客户端使用示例
 * 演示如何使用TEE进行TLS客户端认证的HTTPS请求
 */
public class TeeHttpsExample {
    
    public static void main(String[] args) {
        TeeHttpsExample example = new TeeHttpsExample();
        
        try {
            // 运行基本示例
            example.runBasicExample();
            
            // 运行高级示例
            example.runAdvancedExample();
            
        } catch (Exception e) {
            System.err.println("示例运行失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 基本使用示例
     */
    public void runBasicExample() throws Exception {
        System.out.println("=== TEE HTTPS 基本示例 ===");
        
        // 1. 创建TEE接口实例（在实际应用中，这应该是真实的TEE实现）
        TeeSignatureInterface teeInterface = new MockTeeSignatureImpl();
        
        // 2. 创建TEE OkHttp客户端
        TeeOkHttpClient teeClient = new TeeOkHttpClient(teeInterface, true);
        
        try {
            // 3. 检查TEE可用性
            if (!teeClient.isTeeAvailable()) {
                throw new RuntimeException("TEE不可用");
            }
            
            System.out.println("TEE可用，支持的算法: " + Arrays.toString(teeClient.getSupportedAlgorithms()));
            
            // 4. 构建客户端（测试模式 - 信任所有证书）
            teeClient.buildClient(true);
            System.out.println("OkHttp客户端构建成功");
            
            // 5. 执行HTTPS GET请求
            System.out.println("执行HTTPS GET请求...");
            try (Response response = teeClient.get("https://httpbin.org/get")) {
                System.out.println("响应状态: " + response.code());
                System.out.println("响应头: " + response.headers());
                
                if (response.body() != null) {
                    String responseBody = response.body().string();
                    System.out.println("响应体长度: " + responseBody.length());
                    // 只打印前200个字符
                    if (responseBody.length() > 200) {
                        System.out.println("响应体预览: " + responseBody.substring(0, 200) + "...");
                    } else {
                        System.out.println("响应体: " + responseBody);
                    }
                }
            }
            
        } finally {
            // 6. 清理资源
            teeClient.cleanup();
            System.out.println("资源清理完成");
        }
        
        System.out.println("=== 基本示例完成 ===\n");
    }
    
    /**
     * 高级使用示例
     */
    public void runAdvancedExample() throws Exception {
        System.out.println("=== TEE HTTPS 高级示例 ===");
        
        // 创建TEE接口实例
        TeeSignatureInterface teeInterface = new MockTeeSignatureImpl();
        
        // 创建TEE OkHttp客户端（启用详细日志）
        TeeOkHttpClient teeClient = new TeeOkHttpClient(teeInterface, true);
        
        try {
            // 构建客户端
            teeClient.buildClient(true);
            
            // 执行POST请求
            System.out.println("执行HTTPS POST请求...");
            
            String jsonData = "{\"message\": \"Hello from TEE client\", \"timestamp\": " + System.currentTimeMillis() + "}";
            RequestBody body = RequestBody.create(jsonData, MediaType.get("application/json; charset=utf-8"));
            
            try (Response response = teeClient.post("https://httpbin.org/post", body)) {
                System.out.println("POST响应状态: " + response.code());
                
                if (response.body() != null) {
                    String responseBody = response.body().string();
                    System.out.println("POST响应体长度: " + responseBody.length());
                }
            }
            
            // 演示错误处理
            System.out.println("测试错误处理...");
            try (Response response = teeClient.get("https://httpbin.org/status/404")) {
                System.out.println("404响应状态: " + response.code());
                System.out.println("错误处理测试完成");
            }
            
            // 演示多次请求
            System.out.println("执行多次请求测试...");
            for (int i = 0; i < 3; i++) {
                try (Response response = teeClient.get("https://httpbin.org/uuid")) {
                    if (response.isSuccessful() && response.body() != null) {
                        System.out.println("请求 " + (i + 1) + " 成功: " + response.body().string().trim());
                    }
                }
            }
            
        } finally {
            teeClient.cleanup();
        }
        
        System.out.println("=== 高级示例完成 ===\n");
    }
    
    /**
     * 演示如何与真实的TEE接口集成
     */
    public void demonstrateRealTeeIntegration() {
        System.out.println("=== 真实TEE集成示例 ===");
        
        // 在实际应用中，您需要实现真实的TEE接口
        // 示例代码：
        /*
        // 1. 创建真实的TEE接口实现
        TeeSignatureInterface realTeeInterface = new RealTeeSignatureImpl();
        
        // 2. 配置TEE参数
        realTeeInterface.configure(teeConfig);
        
        // 3. 验证TEE可用性
        if (!realTeeInterface.isAvailable()) {
            throw new RuntimeException("TEE硬件不可用");
        }
        
        // 4. 创建客户端
        TeeOkHttpClient client = new TeeOkHttpClient(realTeeInterface, false);
        
        // 5. 生产环境配置（不信任所有证书）
        client.buildClient(false);
        
        // 6. 执行请求
        Response response = client.get("https://secure-api.company.com/data");
        */
        
        System.out.println("请参考代码注释中的真实TEE集成示例");
        System.out.println("=== 真实TEE集成示例完成 ===\n");
    }
    
    /**
     * 演示错误处理和重试机制
     */
    public void demonstrateErrorHandling() throws Exception {
        System.out.println("=== 错误处理示例 ===");
        
        TeeSignatureInterface teeInterface = new MockTeeSignatureImpl();
        TeeOkHttpClient teeClient = new TeeOkHttpClient(teeInterface, true);
        
        try {
            teeClient.buildClient(true);
            
            // 演示网络错误处理
            try {
                Response response = teeClient.get("https://nonexistent-domain-12345.com");
                System.out.println("意外成功: " + response.code());
            } catch (IOException e) {
                System.out.println("网络错误已正确处理: " + e.getMessage());
            }
            
            // 演示TEE错误处理
            // 在实际应用中，您可能需要处理TEE相关的错误
            System.out.println("TEE错误处理机制已就绪");
            
        } finally {
            teeClient.cleanup();
        }
        
        System.out.println("=== 错误处理示例完成 ===");
    }
}