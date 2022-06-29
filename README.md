

# midatk

#### 介绍

中间人攻击，Diffie-Hellman密钥交换，AES-GCM加密算法，PSK预共享秘钥

#### 软件架构

客户端服务器架构，多线程回射服务器，仿TLS-PSK实现。

#### 使用说明

1. 使用前请先make
2. dist中会生成几个可执行文件，其中server为服务器，client为客户端，mid_server为中间人服务器
3. make过程中可能会要求安装libcrypto库，可去官网下载安装
4. 如果使用PSK预共享秘钥，请在服务器或客户端运行时指明密钥路径


#### 参与贡献

1.  Fork 本仓库
2.  新建 dev 分支
3.  提交代码
4.  新建 Pull Request

#### 任务安排

##### 第一阶段：Diffie-Hellman 协议的实现

- [x] CS客户端服务器及通讯协议实现

  1. 消息格式定义

     | Content Type | Length |   Payload    |
     | :----------: | :----: | :----------: |
     |    1Bytes    | 2Bytes | Length Bytes |

  2. 客户端服务器采用TCP通信

  3. 客户端、服务器采用多线程

     * 服务器：
       * 监听线程
       * 多个客户端通信线程
     * 客户端
       * 发送线程
       * 接收线程

- [x] Diffie-Hellman协议实现

  1. 报文头部

     * 交换Modulus: P和Generator:  g

       ```cpp
       struct DH_hdr
       {
           u_short len_P = LEN_MODULE;
           byte P[LEN_MODULE];
           u_short len_g = LEN_GENERATOR;
           byte g[LEN_GENERATOR];
       };
       ```

       

     * 交换公钥

       ```cpp
       struct Key_change_hdr
       {
           u_short len_pubkey = LEN_PUBLIC_KEY;
           byte pubkey[LEN_PUBLIC_KEY];
       };
       ```

       

  2. 密钥交换步骤

     1. 服务器：计算P, g发送给客户端
     2. 服务器：计算服务器公钥`pubA`，私钥`privA`，发送公钥给客户端
     3. 客户端：接收P, g，计算客户端公钥`pubB`，私钥`privB`，发送公钥给服务器
     4. 客户端：接收服务器公钥`pubA`，计算协商密钥`agreedKey`，发送`CHANGE_CIPHER_SPEC`
     5. 服务器：接收客户端公钥`pubB`，计算协商密钥`agreedKey`，发送`CHANGE_CIPHER_SPEC`
     6. 密钥协商完成

- [x] 主密钥生成

  * HandShake

    ```cpp
    struct HandShake_hdr
    {
        byte type;
        u_short len;
        byte rand[32];
    };
    ```

  * 客户端服务器握手

    * Server Hello
    * Client Hello

  * 密钥扩展
    使用客户端、服务器随机数扩展预主密钥生成主密钥
    
  * 协议结构

    ```cpp
    struct Security_param
    {
        byte client_random[LEN_RANDOM_BYTES];
        byte server_random[LEN_RANDOM_BYTES];
        byte pre_master_secert[LEN_PRE_MASTER_SECRET];
        byte master_secret[LEN_MASTER_SECERT];
    
        // AES Keys and Ivs
        byte client_write_key[LEN_WRITE_KEY];
        byte server_write_key[LEN_WRITE_KEY];
        byte client_write_iv[LEN_WRITE_IV];
        byte server_write_iv[LEN_WRITE_IV];
    };
    ```

- [x] GCM算法加解密实现

  * 加解密函数

    * `data_dec()`
    * `data_enc()`

  * 加密消息格式

    | SeqNo  | Cipher | AuthTag |
    | :----: | :----: | :-----: |
    | 8Bytes | xBytes | 16Bytes |

    

  * 附加认证信息AAD选取

    | SeqNo  | Type  | EncryptedDataLen |
    | :----: | :---: | :--------------: |
    | 8Bytes | 1Byte |      2Bytes      |

##### 第二阶段：Diffie-Hellman 中间人攻击方法研究与实现

这里我们假设有三方主机：A，B，C。其中A为正常用户，B为服务器，C为中间人

- [x] 连接盗用测试
  * Libnet构建ARP包
  * ARP欺骗
- [x] 中间人攻击
  * 中间人扮演两个角色
  
    * 服务器端（A <--> C）
  
      * 处理与客户端通信：
  
        ```cpp
        virtual int deal_appdata_server(char *buf, u_short len_payload, Security_param &sp)
        ```
  
    * 客户端（C <--> B）
  
      * 处理与服务器通信
  
        ```cpp
        virtual int deal_appdata_client(char *buf, u_short len_payload, Security_param &sp);
        ```
  
        

##### 第三阶段：Diffie-Hellman 协议改进

- [x] 预共享秘钥协议实现（PSK协议）

  > In [cryptography](https://en.wikipedia.org/wiki/Cryptography), a **pre-shared key** (**PSK**) is a [shared secret](https://en.wikipedia.org/wiki/Shared_secret) which was previously shared between the two parties using some [secure channel](https://en.wikipedia.org/wiki/Secure_channel) before it needs to be used.

  [Pre-shared key]: https://en.wikipedia.org/wiki/Pre-shared_key

  如果我们使用预共享协议，很大程度上它只是用来对交换密钥进行验证的，这里我们可以使用对称密钥也可以使用非对称密钥，TLS中使用对称密钥对DH协议进行了认证：

  > Let Z be the value produced by this computation (with leading zero bytes stripped as in other Diffie-Hellman-based ciphersuites). Concatenate a uint16 containing the length of Z (in octets), Z itself, a uint16 containing the length of the PSK (in octets), and the PSK itself.

  [RFC4279]: https://datatracker.ietf.org/doc/html/rfc4279#section-3

  下面是`Pre-master key`的结构：

  | Len Shared Secret | Shared Secret | Len PSK |  PSK   |
  | :---------------: | :-----------: | :-----: | :----: |
  |      2Bytes       |    Nbytes     | 2Bytes  | Nbytes |

  由于中间人通过监听无法获得PSK，因此其无法生成对应的`Pre-master key`，

  这里我规定了`Pre-master key`的长度为48字节，方便后续计算，因此可使用合适的安全哈希函数缩减其长度。

  有了`Pre-master key`，后续便可使用[Key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function)来计算`master key`来生成通信密钥。
  
  [^PSK密钥生成]: https://www.helplib.cn/beryl/generate-pre-shared-key-in-linux
  
  
