# SGX-base-File-Hosting

## 功能
### 用户登录 
注册用户 |  注册用户名和密码 
登录用户 | 登录系统 
### 连接本地引擎 
配置本地引擎地址 | 本地模式（需要开启Intel SGX硬件支持，并加载本项目提供的本地引擎docker镜像）和代理模式（默认代理模式） 
连接引擎 | 连接引擎 
### 加密并上传文件 
同步文件到本地引擎 | 同步文件到本地引擎，引擎存储为user_XXX 
生成密钥 | 与服务端可信环境进行安全密钥生成和交换 
加密文件 | 本地引擎采用密钥加密user_XXX文件 
上传文件 | 本地引擎上传加密后的user_XXX文件 
### 审核文件 
解密文件 | 服务器引擎以密钥在可信环境解密文件 
执行审计 | 服务器引擎在可信环境审核文件 
### IPFS 
添加到IPFS网络 | 添加加密文件到IPFS网络 
### 区块链 
哈希上链 | 加密文件的哈希（文件指纹）通过链码上传到超级账本联盟链中 
### 下载文件 
下载文件 | 用户下载服务器端文件 
