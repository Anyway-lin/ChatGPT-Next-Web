package com.example.tls.okhttp;

import com.example.tls.ssl.TeeSSLContextManager;
import com.example.tls.tee.TeeSignatureInterface;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.logging.HttpLoggingInterceptor;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

/**
 * 集成TEE的OkHttp客户端
 * 使用TEE进行TLS客户端认证
 */
public class TeeOkHttpClient {
    
    private final TeeSSLContextManager sslContextManager;
    private OkHttpClient okHttpClient;
    private final boolean enableLogging;
    
    public TeeOkHttpClient(TeeSignatureInterface teeInterface, boolean enableLogging) {
        this.sslContextManager = new TeeSSLContextManager(teeInterface);
        this.enableLogging = enableLogging;
    }
    
    /**
     * 构建OkHttp客户端
     * 
     * @param trustAllCerts 是否信任所有证书（仅用于测试）
     * @return 配置好的OkHttpClient
     * @throws Exception 构建过程中的异常
     */
    public OkHttpClient buildClient(boolean trustAllCerts) throws Exception {
        if (okHttpClient == null) {
            // 检查TEE可用性
            if (!sslContextManager.isTeeAvailable()) {
                throw new IllegalStateException("TEE is not available");
            }
            
            // 创建SSL上下文
            SSLContext sslContext = sslContextManager.createSSLContext(trustAllCerts);
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            
            // 构建OkHttpClient
            OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .sslSocketFactory(sslSocketFactory, getTrustManager(trustAllCerts))
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS);
            
            // 添加日志拦截器（如果启用）
            if (enableLogging) {
                HttpLoggingInterceptor loggingInterceptor = new HttpLoggingInterceptor();
                loggingInterceptor.setLevel(HttpLoggingInterceptor.Level.HEADERS);
                builder.addInterceptor(loggingInterceptor);
            }
            
            // 如果信任所有证书，禁用主机名验证（仅用于测试）
            if (trustAllCerts) {
                builder.hostnameVerifier((hostname, session) -> true);
            }
            
            okHttpClient = builder.build();
        }
        
        return okHttpClient;
    }
    
    /**
     * 执行GET请求
     * 
     * @param url 请求URL
     * @return 响应
     * @throws IOException 请求异常
     */
    public Response get(String url) throws IOException {
        if (okHttpClient == null) {
            throw new IllegalStateException("Client not built. Call buildClient() first.");
        }
        
        Request request = new Request.Builder()
            .url(url)
            .get()
            .build();
        
        return okHttpClient.newCall(request).execute();
    }
    
    /**
     * 执行POST请求
     * 
     * @param url 请求URL
     * @param body 请求体
     * @return 响应
     * @throws IOException 请求异常
     */
    public Response post(String url, okhttp3.RequestBody body) throws IOException {
        if (okHttpClient == null) {
            throw new IllegalStateException("Client not built. Call buildClient() first.");
        }
        
        Request request = new Request.Builder()
            .url(url)
            .post(body)
            .build();
        
        return okHttpClient.newCall(request).execute();
    }
    
    /**
     * 获取原始OkHttpClient实例
     * 
     * @return OkHttpClient实例
     */
    public OkHttpClient getClient() {
        return okHttpClient;
    }
    
    /**
     * 获取支持的签名算法
     * 
     * @return 算法数组
     */
    public String[] getSupportedAlgorithms() {
        return sslContextManager.getSupportedAlgorithms();
    }
    
    /**
     * 检查TEE是否可用
     * 
     * @return true if available
     */
    public boolean isTeeAvailable() {
        return sslContextManager.isTeeAvailable();
    }
    
    /**
     * 清理资源
     */
    public void cleanup() {
        sslContextManager.cleanup();
        
        if (okHttpClient != null) {
            // 关闭连接池
            okHttpClient.dispatcher().executorService().shutdown();
            okHttpClient.connectionPool().evictAll();
        }
    }
    
    /**
     * 获取信任管理器
     * 
     * @param trustAllCerts 是否信任所有证书
     * @return X509TrustManager
     */
    private X509TrustManager getTrustManager(boolean trustAllCerts) {
        if (trustAllCerts) {
            return new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    // 不做检查
                }
                
                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    // 不做检查
                }
                
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
        } else {
            // 返回默认的信任管理器
            try {
                javax.net.ssl.TrustManagerFactory factory = 
                    javax.net.ssl.TrustManagerFactory.getInstance(
                        javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
                factory.init((java.security.KeyStore) null);
                javax.net.ssl.TrustManager[] trustManagers = factory.getTrustManagers();
                
                for (javax.net.ssl.TrustManager tm : trustManagers) {
                    if (tm instanceof X509TrustManager) {
                        return (X509TrustManager) tm;
                    }
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to create default trust manager", e);
            }
            
            throw new RuntimeException("No X509TrustManager found");
        }
    }
}