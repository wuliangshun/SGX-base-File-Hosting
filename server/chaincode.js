/*
chaincode


 
 peer chaincode install -n efs_cc -v v0 -p github.com/efs
 peer chaincode instantiate -o orderer.example.com:7050 -C mychannel -n efs_cc -v v0 -c '{"Args":[]}'
 peer chaincode invoke -n efs_cc -c '{"Args":["initLedger"]}' -C mychannel
 peer chaincode invoke -n efs_cc -c '{"Args":["addUser","wuliangshun","common"]}' -C mychannel
 peer chaincode invoke -n efs_cc -c '{"Args":["addFile","Qmb64o6w185r37cmyjhhSPyKTi7e968o3oLpfHjPN6qiZs","test.txt","wuliangshun"]}' -C mychannel
 peer chaincode invoke -n efs_cc -c '{"Args":["queryFileByHash","Qmb64o6w185r37cmyjhhSPyKTi7e968o3oLpfHjPN6qiZs"]}' -C mychannel


*/

'use strict';

const FabricCAServices = require('fabric-ca-client');
const { FileSystemWallet, Gateway, X509WalletMixin } = require('fabric-network');
const fs = require('fs');
const path = require('path');

const ccpPath = path.resolve(__dirname, '..', 'basic-network', 'connection.json');
const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);

async function enrollAdmin() {
    try {

        // 创建一个CA客户端
        const caURL = ccp.certificateAuthorities['ca.example.com'].url;
        const ca = new FabricCAServices(caURL);

        // 创建一个wallet文件夹，用于管理身份.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = new FileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

        // 检查是否已经注册管理员.
        const adminExists = await wallet.exists('admin');
        if (adminExists) {
            console.log('An identity for the admin user "admin" already exists in the wallet');
            return;
        }

        // 向ca服务器注册管理员,并将从服务器获得的身份证书导入到wallet.
        const enrollment = await ca.enroll({ enrollmentID: 'admin', enrollmentSecret: 'adminpw' });
        const identity = X509WalletMixin.createIdentity('Org1MSP', enrollment.certificate, enrollment.key.toBytes());
        wallet.import('admin', identity);
        console.log('Successfully enrolled admin user "admin" and imported it into the wallet');

    } catch (error) {
        console.error(`Failed to enroll admin user "admin": ${error}`);
        process.exit(1);
    }
}


async function invoke(func, ...args) {
	
	try {
		
		 // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = new FileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists('admin');
        if (!userExists) {
            console.log('An identity for the user "admin" does not exist in the wallet');
            console.log('Please init the ledger before retrying');
            return;
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: 'admin', discovery: { enabled:  false} });//*/true, asLocalhost: true
		
        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');
		
        // Get the contract from the network.
        //console.dir(network);
        //console.log("------------------")
        //console.log(network.contracts);
        const contract = network.getContract('efs_cc');

        // Submit the specified transaction.
        await contract.submitTransaction(func, ...args);
        console.log('Chaincode invoked! ');
	
        // Disconnect from the gateway.
        await gateway.disconnect();

    } catch (error) {
        console.error(`Failed to submit transaction: ${error}`);
        //process.exit(1);
    }
}


async function query(func, ...args) {
    try {

        // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = new FileSystemWallet(walletPath);
        console.log(`wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists('admin');
        if (!userExists) {
            console.log('An identity for the user "admin" does not exist in the wallet');
            console.log('Run the enrollAdmin.js application before retrying');
            return;
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccp, { wallet, identity: 'admin', discovery: { enabled: true, asLocalhost: true } });

        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');

        // Get the contract from the network.
        const contract = network.getContract('efs_cc');

        // Evaluate the specified transaction.
        const result = await contract.evaluateTransaction(func, ...args);
        console.log(`Transaction has been evaluated, result is: ${result.toString()}`);

    } catch (error) {
        console.error(`Failed to evaluate transaction: ${error}`);
        //process.exit(1);
    }
}


module.exports = {
 enrollAdmin,
 invoke,
 query
}
