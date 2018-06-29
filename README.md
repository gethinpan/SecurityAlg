# SecurityAlg
> 本项目是东南大学网络信息安全课程的大作业，使用Java实现常见安全算法，包括DES，AES，MD5，
> SHA，RSA等，在此基础设计了一个包含GUI的应用，要求如下：

![流程图](https://github.com/gethinpan/SecurityAlg/blob/master/src/resource/image/flow.png)

>图中M 表示明文， H 表示 Hash 函数， E 表示加密算法， D 表示解密算法， RKA表示发送方 A 的私钥， UKA表
>示发送方 A 的公钥， RKB表示发送方 B 的私钥， UKB表示发送方 B 的公钥， ||表示组合。阴影部分表示加密后的结果。

 
 ## 安全算法使用说明
 ### 对称加密算法
 >对称加密算法包括 DES 和 AES，API 接口相同，以下用 SymEnc 来指代 DES 或 AES
 ``` java
 // iniKey为8-byte（DES）或16-byte（AES）的初始密钥
 SymEnc symEnc = new SymEnc(iniKey);
 // 加密，msg为明文消息的字节数组，返回加密后密文消息的字节数组
 byte[] encrypted = symEnc.encrypt(msg);
 // 解密，encrypted为密文消息的字节数组，返回解密后的明文消息的字节数组
 byte[] decrypted = symEnc.decrypt(encrypted);
 ```
 
 ### Hash 函数
 >Hash 函数包括 MD5, SHA224, SHA256, SHA384, SHA512，其中 SHA224 和 SHA256 在类 SHA2 中实现，SHA384 和 SHA512 
 >在类 SHA5 中实现，SHA384 和 SHA512 在类 SHA5 中实现，API接口相同，以下用Hash来指导 MD5, SHA224, SHA256, SHA384或
 >SHA512。
  ``` java 
  Hash hash = new Hash();
  // msg1 和 msg2 是用字节数组表示的消息的一部分
  // 消息可分段传递给update函数
  hash.update(msg1);
  hash.update(msg2);
  ...
  // 获取最终消息摘要
  hash.getDigest();
  ```
  
  ### 非对称加密算法
  >非对称加密算法包括RSA，分为两部分实现，在类RSAKey中实现根据指定长度生成RSA公私钥对，在类RSA中实现加密，解密，
  >签名，验证的功能，具体内容参考PKCS#1 V2.1。
  >RSAKey类API使用如下:
  ``` java 
  // keySize 为密钥模数长度
  RSAKey rsaKey = new RSAKey(keySize);
  // 生成公私钥对
  RSAKey.KeyPair keyPair = rsaKey.generateKeyPair();
  // 获取公钥
  RSAKey.PublicKey publicKey = keyPair.getPublicKey();
  // 获取私钥
  RSAKey.PrivateKey privateKey = keyPair.getPrivateKey();
  // 获取公钥指数e
  BigInteger e = publicKey.getPublicExponent();
  // 获取私钥指数d
  BigInteger d = privateKey.getPrivateExponent();
  // 获取密钥模数n
  BigInteger n = publicKey.getModule();
  BigInteger n = privateKey.getModule();
  ```
  
  >RSA类API使用如下：
  ``` java 
  // mode 工作模式为，privateKey为私钥，在输入私钥情况下，mode只能为2（解密）或3（签名）
  RSA rsa = new RSA(mode, privateKey);
  // 在输入公钥情况下，mode只能为1（加密）或4（验证）
  RSA rsa = new RSA(mode, publicKey);
  // 根据输入模式和密钥对消息字节msg进行处理，返回相应结果
  byte[] output = rsa.process(msg);
  ```
  
  ## APP说明
  >AppMainWindow 为主入口类，UI参考[WeSync](https://github.com/rememberber/WeSync)实现
  
  ### 环境依赖
  > Java 7
  
  ### 速览
  ![参数设定界面](https://github.com/gethinpan/SecurityAlg/blob/master/src/resource/image/parameterPanel.png)
  ![加密发送界面](https://github.com/gethinpan/SecurityAlg/blob/master/src/resource/image/sendPanel.png)
  ![接收解密界面](https://github.com/gethinpan/SecurityAlg/blob/master/src/resource/image/receivePanel.png)
  
  ### 使用说明
  >1. 在加密参数设定界面选择并输入安全算法参数，也可使用系统默认的参数；
  >2. 在加密发送界面输入需要发送的明文消息，点击发送按钮；
  >3. 在解密认证界面，收到的密文消息会以Base64编码的形式显示在密文文本框中，点击解密按钮，会在明文文本框中获得
  >解密后的明文、数字签名等信息，点击认证按钮，会进行数字签名认证，认证结果显示在明文文本框中。
  
  ### 声明
  >图标来源：http://designmodo.com/linecons-free/
  

