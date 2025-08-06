package com.example.tls.ssl;

import com.example.tls.tee.TeeSignatureInterface;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * TEE SSL上下文管理器
 * 负责创建和配置使用TEE签名的SSL上下文
 */
public class TeeSSLContextManager {
    
    private final TeeSignatureInterface teeInterface;
    private final TeeSignatureProvider teeProvider;
    private SSLContext sslContext;
    
    public TeeSSLContextManager(TeeSignatureInterface teeInterface) {
        this.teeInterface = teeInterface;
        this.teeProvider = new TeeSignatureProvider();
        
        // 注册TEE提供者
        Security.addProvider(teeProvider);
    }
    
    /**
     * 创建并配置SSL上下文
     * 
     * @param trustAllCerts 是否信任所有证书（仅用于测试）
     * @return 配置好的SSLContext
     * @throws Exception 创建过程中的异常
     */
    public SSLContext createSSLContext(boolean trustAllCerts) throws Exception {
        if (sslContext == null) {
            sslContext = SSLContext.getInstance("TLS");
            
            // 创建KeyManager数组
            KeyManager[] keyManagers = createKeyManagers();
            
            // 创建TrustManager数组
            TrustManager[] trustManagers = createTrustManagers(trustAllCerts);
            
            // 初始化SSL上下文
            sslContext.init(keyManagers, trustManagers, new SecureRandom());
        }
        
        return sslContext;
    }
    
    /**
     * 获取已创建的SSL上下文
     * 
     * @return SSL上下文，如果未创建则返回null
     */
    public SSLContext getSSLContext() {
        return sslContext;
    }
    
    /**
     * 创建KeyManager数组
     * 
     * @return KeyManager数组
     */
    private KeyManager[] createKeyManagers() {
        String alias = "tee-client-cert";
        TeeX509KeyManager keyManager = new TeeX509KeyManager(teeInterface, alias);
        return new KeyManager[]{keyManager};
    }
    
    /**
     * 创建TrustManager数组
     * 
     * @param trustAllCerts 是否信任所有证书
     * @return TrustManager数组
     */
    private TrustManager[] createTrustManagers(boolean trustAllCerts) {
        if (trustAllCerts) {
            // 仅用于测试 - 信任所有证书
            return new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                        // 不做任何检查
                    }
                    
                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                        // 不做任何检查
                    }
                    
                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
            };
        } else {
            // 使用默认的信任管理器
            return null; // 这将使用系统默认的信任存储
        }
    }
    
    /**
     * 检查TEE是否可用
     * 
     * @return true if TEE is available
     */
    public boolean isTeeAvailable() {
        return teeInterface != null && teeInterface.isAvailable();
    }
    
    /**
     * 获取支持的签名算法
     * 
     * @return 支持的算法数组
     */
    public String[] getSupportedAlgorithms() {
        return teeInterface != null ? teeInterface.getSupportedAlgorithms() : new String[0];
    }
    
    /**
     * 清理资源
     */
    public void cleanup() {
        if (teeProvider != null) {
            Security.removeProvider(teeProvider.getName());
        }
    }
}