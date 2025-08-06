package com.example.teetls

import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.*
import okhttp3.*
import java.io.IOException

/**
 * 主Activity
 * 演示如何使用基于TEE的自定义TLS引擎进行HTTP请求
 */
class MainActivity : AppCompatActivity() {
    
    companion object {
        private const val TAG = "MainActivity"
    }
    
    private lateinit var statusTextView: TextView
    private lateinit var testButton: Button
    private lateinit var okHttpClient: OkHttpClient
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        initializeViews()
        initializeOkHttpClient()
        setupClickListeners()
    }
    
    private fun initializeViews() {
        statusTextView = findViewById(R.id.statusTextView)
        testButton = findViewById(R.id.testButton)
    }
    
    private fun initializeOkHttpClient() {
        try {
            // 创建集成TEE的OkHttp客户端
            okHttpClient = TEEOkHttpClient.create()
            updateStatus("TEE OkHttp客户端初始化成功")
            Log.d(TAG, "TEE OkHttp客户端初始化成功")
        } catch (e: Exception) {
            updateStatus("TEE OkHttp客户端初始化失败: ${e.message}")
            Log.e(TAG, "TEE OkHttp客户端初始化失败", e)
        }
    }
    
    private fun setupClickListeners() {
        testButton.setOnClickListener {
            testTEEHttpsRequest()
        }
    }
    
    /**
     * 测试基于TEE的HTTPS请求
     */
    private fun testTEEHttpsRequest() {
        testButton.isEnabled = false
        updateStatus("正在测试TEE HTTPS请求...")
        
        // 使用协程进行网络请求
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // 测试HTTPS请求
                val request = Request.Builder()
                    .url("https://httpbin.org/get")
                    .addHeader("User-Agent", "TEE-OkHttp-Client/1.0")
                    .build()
                
                Log.d(TAG, "发送TEE HTTPS请求: ${request.url}")
                
                okHttpClient.newCall(request).enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) {
                        runOnUiThread {
                            updateStatus("TEE HTTPS请求失败: ${e.message}")
                            testButton.isEnabled = true
                        }
                        Log.e(TAG, "TEE HTTPS请求失败", e)
                    }
                    
                    override fun onResponse(call: Call, response: Response) {
                        runOnUiThread {
                            if (response.isSuccessful) {
                                updateStatus("TEE HTTPS请求成功！\n状态码: ${response.code}\n协议: ${response.protocol}")
                                Log.d(TAG, "TEE HTTPS请求成功，状态码: ${response.code}")
                                
                                // 输出响应头信息
                                response.headers.forEach { header ->
                                    Log.d(TAG, "响应头: ${header.first} = ${header.second}")
                                }
                                
                                // 测试TEE签名验证
                                testTEESignatureVerification()
                            } else {
                                updateStatus("TEE HTTPS请求失败，状态码: ${response.code}")
                                Log.w(TAG, "TEE HTTPS请求失败，状态码: ${response.code}")
                            }
                            testButton.isEnabled = true
                        }
                        response.close()
                    }
                })
                
            } catch (e: Exception) {
                runOnUiThread {
                    updateStatus("TEE HTTPS请求异常: ${e.message}")
                    testButton.isEnabled = true
                }
                Log.e(TAG, "TEE HTTPS请求异常", e)
            }
        }
    }
    
    /**
     * 测试TEE签名验证
     */
    private fun testTEESignatureVerification() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val teeKeyManager = TEEKeyManager()
                val testData = "TEE签名测试数据".toByteArray()
                
                // 使用TEE进行签名
                val signature = teeKeyManager.signWithTEE(testData)
                
                // 验证签名
                val isValid = teeKeyManager.verifyTEESignature(testData, signature)
                
                runOnUiThread {
                    val currentStatus = statusTextView.text.toString()
                    updateStatus("$currentStatus\nTEE签名验证: ${if (isValid) "成功" else "失败"}")
                }
                
                Log.d(TAG, "TEE签名验证结果: $isValid")
            } catch (e: Exception) {
                runOnUiThread {
                    val currentStatus = statusTextView.text.toString()
                    updateStatus("$currentStatus\nTEE签名验证异常: ${e.message}")
                }
                Log.e(TAG, "TEE签名验证异常", e)
            }
        }
    }
    
    /**
     * 更新状态文本
     */
    private fun updateStatus(status: String) {
        statusTextView.text = status
        Log.d(TAG, "状态更新: $status")
    }
    
    override fun onDestroy() {
        super.onDestroy()
        // 清理资源
        if (::okHttpClient.isInitialized) {
            okHttpClient.dispatcher.executorService.shutdown()
        }
    }
}