config文件需要自己创建，按照自己的需求进行创建
v1:  g++  main.cc CryptoUtil.cc -o server -lworkflow -lwfrest -lssl -lcrypto -ljwt
// 依次运行即可
v2:  mkdir build && cd build && cmake .. && make && cd ../.. && ./server 
v4: v4需要创建一个bin文件夹，并且把static文件夹放在bin文件夹下面
// OSS_config.json
{
    "endpoint": "",
    "accessKeyId": "",
    "accessKeySecret":""
}

// RabbitMQ_config.json
{
    "host":"",
    "port":,
    "username":"",
    "password":"",
    "vhost":"",
    "exchange":"",
    "routing_key" :"",
    "uri":"",
    "queue":""
}
// uri 参考： amqp://guest:guest@localhost:5672/%2f