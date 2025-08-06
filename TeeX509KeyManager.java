package com.example.tls.ssl;

import com.example.tls.tee.TeeSignatureInterface;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.Signature;

/**
 * 自定义X509KeyManager，使用TEE进行签名操作
 * 不直接暴露私钥，而是通过TEE接口进行签名
 */
public class TeeX509KeyManager implements X509KeyManager {
    
    private final TeeSignatureInterface teeInterface;
    private final String alias;
    
    public TeeX509KeyManager(TeeSignatureInterface teeInterface, String alias) {
        this.teeInterface = teeInterface;
        this.alias = alias;
    }
    
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        if (isKeyTypeSupported(keyType)) {
            return new String[]{alias};
        }
        return null;
    }
    
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        for (String type : keyType) {
            if (isKeyTypeSupported(type)) {
                return alias;
            }
        }
        return null;
    }
    
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        // 客户端不需要实现服务器相关方法
        return null;
    }
    
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        // 客户端不需要实现服务器相关方法
        return null;
    }
    
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        if (this.alias.equals(alias)) {
            try {
                return teeInterface.getCertificateChain();
            } catch (Exception e) {
                throw new RuntimeException("Failed to get certificate chain from TEE", e);
            }
        }
        return null;
    }
    
    @Override
    public PrivateKey getPrivateKey(String alias) {
        if (this.alias.equals(alias)) {
            // 返回一个代理私钥，不暴露真实私钥
            return new TeePrivateKey(teeInterface);
        }
        return null;
    }
    
    private boolean isKeyTypeSupported(String keyType) {
        // 支持RSA和ECDSA
        return "RSA".equals(keyType) || "EC".equals(keyType);
    }
    
    /**
     * 代理私钥类，将签名操作委托给TEE
     */
    private static class TeePrivateKey implements PrivateKey {
        private final TeeSignatureInterface teeInterface;
        
        public TeePrivateKey(TeeSignatureInterface teeInterface) {
            this.teeInterface = teeInterface;
        }
        
        @Override
        public String getAlgorithm() {
            return "RSA"; // 或根据实际情况返回
        }
        
        @Override
        public String getFormat() {
            return null; // 不支持格式化输出
        }
        
        @Override
        public byte[] getEncoded() {
            return null; // 不暴露私钥内容
        }
        
        // 注意：这个类主要是为了满足接口要求
        // 实际的签名操作通过TeeSignatureProvider处理
    }
}