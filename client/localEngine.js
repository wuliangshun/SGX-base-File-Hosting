const http = require("http")
const url = require("url")
const queryString = require("querystring")
const path = require('path');
const fs = require('fs');
const bufferSplit = require('./bufferSplit')



function postFile(fileKeyValue, req) {
  var boundaryKey = Math.random().toString(16);
  var enddata = '\r\n----' + boundaryKey + '--';
 
  var files = new Array();
  for (var i = 0; i < fileKeyValue.length; i++) {
   var content = "\r\n----" + boundaryKey + "\r\n" + "Content-Type: application/octet-stream\r\n" + "Content-Disposition: form-data; name=\"" + fileKeyValue[i].urlKey + "\"; filename=\"" + path.basename(fileKeyValue[i].urlValue) + "\"\r\n" + "Content-Transfer-Encoding: binary\r\n\r\n";
   var contentBinary = new Buffer(content, 'utf-8');//当编码为ascii时，中文会乱码。
   files.push({contentBinary: contentBinary, filePath: fileKeyValue[i].urlValue});
  }
  var contentLength = 0;
  for (var i = 0; i < files.length; i++) {
   var stat = fs.statSync(files[i].filePath);
   contentLength += files[i].contentBinary.length;
   contentLength += stat.size;
  }
 
  req.setHeader('Content-Type', 'multipart/form-data; boundary=--' + boundaryKey);
  req.setHeader('Content-Length', contentLength + Buffer.byteLength(enddata));
 
  // 将参数发出
  var fileindex = 0;
  var doOneFile = function(){
   req.write(files[fileindex].contentBinary);
   var fileStream = fs.createReadStream(files[fileindex].filePath, {bufferSize : 4 * 1024});
   fileStream.pipe(req, {end: false});
   fileStream.on('end', function() {
     fileindex++;
     if(fileindex == files.length){
      req.end(enddata);
     } else {
      doOneFile();
     }
   });
  };
  if(fileindex == files.length){
    req.end(enddata);
  } else {
    doOneFile();
  }      
}

var RemoteEngineIP = "localhost"
var RemoteEnginePort = "12581"



const server = http.createServer((req,res)=>{
    res.setHeader("Access-Control-Allow-Origin", "*");
    let methods = req.method;
    console.log("Current access type:"+ methods);
    if(methods == "GET"){
        let params = url.parse(req.url,true,true);
        console.log(params) 
        res.setHeader("content-type","text/html;charset=UTF-8")
		
		//GET    
		/*
		http://127.0.0.1:8002/upload?username=wuliangshun&filepath=sgx_protect_file/encrypted_example.txt  
		http://127.0.0.1:8002/encrypt?filepath=sgx_protect_file/encrypted_example.txt  
		*/
		try {
			if(params.pathname.includes("connect")){
				res.end("Local engine connected successfully!");
			}else if(params.pathname.includes('generate')){
             var msg = "=================  Generating key ==================";
             var json = {
                  "HttpResponse": ["recv: Msg0"],
                  "DecResult": ["`ϕ`","`k_(u_i )`"],
                  "HttpRequest":  ["send: Msg1"],
                  "HttpResponse": ["recv: Msg2"],
                  "VerifyResult": ["success"]
             }
             var string = JSON.stringify(json);
             msg += "<br>" + string; 
             msg = msg.replace(new RegExp(/(,\")/g),",<br>\"");
             msg = msg.replace(new RegExp(/({)/g),"{<br>");
             msg = msg.replace(new RegExp(/(})/g),"<br>}");
             res.end(msg);   
        }else if(params.pathname.includes('encrypt')){
           var username = params.query.username;
				var filepath = params.query.filepath;
           var msg = "===================  Encrypt files ===================";
				var exec = require('child_process').exec;
				var cmdStr = './app encrypt -i ' + filepath + ' -u ' + username;
				exec(cmdStr, function(err,stdout,stderr){
    				if(err) {
       					 console.log('get weather api error:'+stderr);
    				} else {
        				console.log(stdout);
                var json = {
                  "SynStatus": ["Synchronize "+filepath+" to the local engine ..."],
                  "EncResult": [stdout],
                 }
                var string = JSON.stringify(json);
                msg += "<br>" + string;
                msg = msg.replace(new RegExp(/(,\")/g),",<br>\"");
                msg = msg.replace(new RegExp(/({)/g),"{<br>");
                msg = msg.replace(new RegExp(/(})/g),"<br>}");
						res.end(msg);
    				}
				});
			}else if(params.pathname.includes('upload')){
				var username = params.query.username;
				var filepath = params.query.filepath;
				var files = [{
					urlKey: username, 
					urlValue: filepath
				}]
				console.log(username + "," + filepath);
				var optionsPost = { 
				 	host: RemoteEngineIP, 
					port: RemoteEnginePort, 
					method: "POST", 
					path: "/Upload"
				}
				var req = http.request(optionsPost, function(res_post){
				 	console.log("RES:" + res_post);
					console.log('STATUS: ' + res_post.statusCode);
				 	console.log('HEADERS: ' + JSON.stringify(res_post.headers));
				 	//res.setEncoding("utf8");
				 	res_post.on("data", function(chunk){
                console.log("BODY:" + chunk);
                var msg = "=================  Upload files ====================";
                msg += "<br>" + chunk;
                msg = msg.replace(new RegExp(/(,\")/g),",<br>\"");
                msg = msg.replace(new RegExp(/({)/g),"{<br>");
                msg = msg.replace(new RegExp(/(})/g),"<br>}");
                res.end(msg);
				 })
				})
				req.on('error', function(e){
				 	console.log('problem with request:' + e.message);
				 	console.log(e);
				})
           postFile(files, req);  
			}else if(params.pathname.includes('encrypt')){
				var filepath = params.query.filepath;
				console.log("Encrypt file: " + filepath)
				
			}
		} catch (error) {
			console.error(`error: ${error}`);
		}
    }else if(methods == "POST"){
       //upload file
		  const boundary = `--${req.headers['content-type'].split('; ')[1].split('=')[1]}`  // 获取分隔符
		  let arr = []

		  req.on('data', (buffer) => {
			arr.push(buffer)
		  })

		  req.on('end', () => {
			const buffer = Buffer.concat(arr)
			console.log(buffer.toString())

			// 1. 用<分隔符>切分数据
			let result = bufferSplit(buffer, boundary)
			console.log(result.map(item => item.toString()))

			// 2. 删除数组头尾数据
			result.pop()
			result.shift()
			console.log(result.map(item => item.toString()))

			// 3. 将每一项数据头尾的的\r\n删除
			result = result.map(item => item.slice(2, item.length - 2))
			console.log(result.map(item => item.toString()))

			// 4. 将每一项数据中间的\r\n\r\n删除，得到最终结果
			result.forEach(item => {
			  console.log(bufferSplit(item, '\r\n\r\n').map(item => item.toString()))

			  let [info, data] = bufferSplit(item, '\r\n\r\n')  // 数据中含有文件信息，保持为Buffer类型

			  info = info.toString()  // info为字段信息，这是字符串类型数据，直接转换成字符串，若为文件信息，则数据中含有一个回车符\r\n，可以据此判断数据为文件还是为普通数据。

			  if (info.indexOf('\r\n') >= 0) {  // 若为文件信息，则将Buffer转为文件保存
				// 获取字段名
				let infoResult = info.split('\r\n')[1].split('; ')
				console.log("info:" + info)				
           var reg = /filename="(.*)"/;
           console.log("res:"+ reg.exec(info));
           var filename = reg.exec(info)[1]

				// 将文件存储到服务器
				fs.writeFile("./user_"+filename, data, err => {
				  if (err) {
					console.log(err)
				  } else {
					console.log('文件上传成功');
             //res.end("File has been synchronized to local engine.");
            }
				})
			  } else {  // 若为数据，则直接获取字段名称和值
               let name = info.split('; ')[1].split('=')[1]
				    name = name.substring(1, name.length - 1)
				    const value = data.toString()
				    console.log(name, value)
			  }
			})
		  })
   }
})



server.listen(12582,()=>{
    console.log("local engine is ready on port 12582")
})
