package com.example.tls.tee;

import java.security.cert.X509Certificate;

/**
 * TEE (Trusted Execution Environment) 签名接口
 * 用于在可信执行环境中进行数字签名操作
 */
public interface TeeSignatureInterface {
    
    /**
     * 使用TEE中的私钥对数据进行签名
     * 
     * @param data 需要签名的数据
     * @param algorithm 签名算法 (如 "SHA256withRSA", "SHA256withECDSA")
     * @return 签名结果
     * @throws Exception 签名过程中的异常
     */
    byte[] sign(byte[] data, String algorithm) throws Exception;
    
    /**
     * 获取TEE中存储的证书链
     * 
     * @return X509证书数组，第一个为客户端证书，后续为中间证书
     * @throws Exception 获取证书时的异常
     */
    X509Certificate[] getCertificateChain() throws Exception;
    
    /**
     * 获取支持的签名算法列表
     * 
     * @return 支持的算法名称数组
     */
    String[] getSupportedAlgorithms();
    
    /**
     * 检查TEE是否可用
     * 
     * @return true if TEE is available and functional
     */
    boolean isAvailable();
}