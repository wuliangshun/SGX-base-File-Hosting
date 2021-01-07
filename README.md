# SGX-base-File-Hosting
Achieving Reconciliation between Privacy Preservation and Auditability For File Hosting (Blockchain Specified).

## Technologies

Intel SGX + IPFS + Hyperledger Fabric

## Demo addr
http://111.47.7.227:12580/

## Functionalities
|  Function  |  Description|
|  ----  | ----  |
| 配置本地引擎地址 | 本地模式（需要开启Intel SGX硬件支持，并加载本项目提供的本地引擎docker镜像）和代理模式（默认代理模式） |
| 连接引擎 | 连接引擎 |
| 同步文件到本地引擎 | 同步文件到本地引擎，引擎存储为user_XXX |
| 生成密钥 | 与服务端可信环境进行安全密钥生成和交换 |
| 加密文件 | 本地引擎采用密钥加密user_XXX文件| 
| 上传文件 | 本地引擎上传加密后的user_XXX文件 |
| 解密文件 | 服务器引擎以密钥在可信环境解密文件 |
| 执行审计 | 服务器引擎在可信环境审核文件 |
| 添加到IPFS网络 | 添加加密文件到IPFS网络 |
| 哈希上链 | 加密文件的哈希（文件指纹）通过链码上传到超级账本联盟链中 |
| 下载文件 | 用户下载服务器端文件 |

## Run The Project
#### Run Web Server

`$ cd ./server`

`$ node WebServer.js`

#### Run Server Engine

`$ cd ./server`

`$ node RemoteEngine.js

#### Run Local Engine

`$ cd ./client`

`$ node localEngine.js`

#### Start Fabric

`$ cd $GOPATH/src/github.com/hyperledger/fabric/scripts/fabric-samples/basic-network`

`$ docker-compose -f docker-compose.yml up -d`

`$ docker exec -e "CORE_PEER_LOCALMSPID=Org1MSP" -e "CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/msp/users/Admin@org1.example.com/msp" peer0.org1.example.com peer channel create -o orderer.example.com:7050 -c mychannel -f /etc/hyperledger/configtx/channel.tx`

`$ docker exec -e "CORE_PEER_LOCALMSPID=Org1MSP" -e "CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/msp/users/Admin@org1.example.com/msp" peer0.org1.example.com peer channel join -b mychannel.block`

`$ docker exec -it cli /bin/bash`

`$ peer chaincode install -n efs_cc -v v0 -p github.com/efs`

`$ peer chaincode instantiate -o orderer.example.com:7050 -C mychannel -n efs_cc -v v0 -c '{"Args":[]}'`
 
`$ peer chaincode invoke -n efs_cc -c '{"Args":["initLedger"]}' -C mychannel`

#### Start IPFS

`$ ipfs daemon`

