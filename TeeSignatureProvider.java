package com.example.tls.ssl;

import com.example.tls.tee.TeeSignatureInterface;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

/**
 * TEE签名提供者，将签名操作委托给TEE接口
 */
public class TeeSignatureProvider extends Provider {
    
    private static final String PROVIDER_NAME = "TEEProvider";
    private static final String PROVIDER_VERSION = "1.0";
    private static final String PROVIDER_INFO = "TEE Signature Provider";
    
    public TeeSignatureProvider() {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_INFO);
        
        // 注册支持的签名算法
        put("Signature.SHA256withRSA", TeeSignatureSpi.class.getName());
        put("Signature.SHA384withRSA", TeeSignatureSpi.class.getName());
        put("Signature.SHA512withRSA", TeeSignatureSpi.class.getName());
        put("Signature.SHA256withECDSA", TeeSignatureSpi.class.getName());
    }
    
    /**
     * TEE签名SPI实现
     */
    public static class TeeSignatureSpi extends SignatureSpi {
        
        private TeeSignatureInterface teeInterface;
        private String algorithm;
        private byte[] data;
        private int dataLength;
        
        public TeeSignatureSpi() {
            // 默认构造函数
        }
        
        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            throw new UnsupportedOperationException("Verification not supported in TEE provider");
        }
        
        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            if (privateKey instanceof TeeX509KeyManager.TeePrivateKey) {
                // 从私钥中提取TEE接口
                try {
                    java.lang.reflect.Field field = privateKey.getClass().getDeclaredField("teeInterface");
                    field.setAccessible(true);
                    this.teeInterface = (TeeSignatureInterface) field.get(privateKey);
                } catch (Exception e) {
                    throw new InvalidKeyException("Failed to access TEE interface from private key", e);
                }
            } else {
                throw new InvalidKeyException("Expected TeePrivateKey, got: " + privateKey.getClass());
            }
            
            // 初始化数据缓冲区
            this.data = new byte[8192]; // 初始大小
            this.dataLength = 0;
        }
        
        @Override
        protected void engineUpdate(byte b) throws SignatureException {
            ensureCapacity(1);
            data[dataLength++] = b;
        }
        
        @Override
        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
            ensureCapacity(len);
            System.arraycopy(b, off, data, dataLength, len);
            dataLength += len;
        }
        
        @Override
        protected byte[] engineSign() throws SignatureException {
            if (teeInterface == null) {
                throw new SignatureException("TEE interface not initialized");
            }
            
            try {
                // 获取要签名的数据
                byte[] dataToSign = new byte[dataLength];
                System.arraycopy(data, 0, dataToSign, 0, dataLength);
                
                // 通过TEE接口进行签名
                return teeInterface.sign(dataToSign, algorithm);
            } catch (Exception e) {
                throw new SignatureException("TEE signing failed", e);
            }
        }
        
        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            throw new UnsupportedOperationException("Verification not supported in TEE provider");
        }
        
        @Override
        protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
            if ("algorithm".equals(param) && value instanceof String) {
                this.algorithm = (String) value;
            } else {
                throw new InvalidParameterException("Unsupported parameter: " + param);
            }
        }
        
        @Override
        protected Object engineGetParameter(String param) throws InvalidParameterException {
            if ("algorithm".equals(param)) {
                return algorithm;
            }
            throw new InvalidParameterException("Unknown parameter: " + param);
        }
        
        private void ensureCapacity(int additionalLength) {
            int requiredLength = dataLength + additionalLength;
            if (requiredLength > data.length) {
                // 扩展数组大小
                byte[] newData = new byte[Math.max(requiredLength, data.length * 2)];
                System.arraycopy(data, 0, newData, 0, dataLength);
                data = newData;
            }
        }
    }
}