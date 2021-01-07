/*

Local Web Server

*/


let express = require('express');
let fs = require('fs');
let path = require('path');
 
 
var app = express();
 
app.use(express.static(__dirname));
 
app.all('/', function(req, res){
  console.log("=======================================");
  console.log("url:"+req.url);
  var filename = req.url.split('/')[req.url.split('/').length-1];
  var suffix = req.url.split('.')[req.url.split('.').length-1];
  console.log("filename:", filename);
  if(req.url==='/'){
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.end(get_file_content(path.join(__dirname, 'Html', 'index.html')));
  }else if(suffix==='css'){
    res.writeHead(200, {'Content-Type': 'text/css'});
    res.end(get_file_content(path.join(__dirname, 'css', filename)));
  }else if(suffix in ['gif', 'jpeg', 'jpg', 'png']) {
    res.writeHead(200, {'Content-Type': 'image/'+suffix});
    res.end(get_file_content(path.join(__dirname,'images', filename)));
  }
});
 
 
function get_file_content(filepath){
  return fs.readFileSync(filepath);
}

port = 12580;
console.log("server is ready on port " + port);
app.listen(port);

