# 版本区分：
## v1：基本实现
> 实现 web 网盘项目的基本功能：注册，登录，获取用户信息，展示文件列表，上传文件，下载文件。
> 
> ```sql
> CREATE TABLE `tbl_user` (
>   `id` int NOT NULL AUTO_INCREMENT,
>   `username` varchar(255) NOT NULL,
>   `password` varchar(255) NOT NULL,
>   `salt` varchar(64) NOT NULL,
>   `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
>   `tomb` int DEFAULT '0',
>   PRIMARY KEY (`id`),
>   UNIQUE KEY `username` (`username`)
> ) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 
> COLLATE=utf8mb4_0900_ai_ci
> ```
> 
> ```sql
> CREATE TABLE `tbl_file` (
>   `id` int NOT NULL AUTO_INCREMENT,
>   `uid` int NOT NULL,
>   `filename` varchar(255) NOT NULL,
>   `hashcode` varchar(255) NOT NULL,
>   `size` bigint DEFAULT '0',
>   `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
>   `last_update` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE 
> CURRENT_TIMESTAMP,
>   `status` int DEFAULT '0' COMMENT '状态(可用/禁用/已删除等)',
>   PRIMARY KEY (`id`)
> ) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 
> COLLATE=utf8mb4_0900_ai_ci
> ```

## v2：云服务
> 实现云服务，用阿里云oss备份文件
> 下载安装 [OSS C++ SDK](https://help.aliyun.com/zh/oss/developer-reference/cpp/?spm=a2c4g.11186623.0.i1)

## v3：消息队列
> 使用RabbitMQ消息队列对oss上传文件进行处理
> docker启动语句
> ```docker
> docker run -d --hostname rabbitsrv --name rabbit -p 5672:5672 -p 15672:15672 -p 25672:25672 -v /data/rabbitmq:/var/lib/rabbitmq rabbitmq:management
> ```

## v4：rpc通信
> 使用rpc通信将用户的登录注册分离出来
> 生成文件相应语句，其中example.proto根据需求进行修改
> ```shell
>  protoc --cpp_out=./ example.proto
>  srpc_generator protobuf example.proto ./
> ```
## 启动方法
-  v1:  g++  main.cc CryptoUtil.cc -o server -lworkflow -lwfrest -lssl -lcrypto -ljwt
 // 依次运行即可
-  v2: 
    > ```shell
    > mkdir build 
    > cd build 
    > cmake .. 
    > make 
    > cd ../.. && ./server 
    > ```
-  v3:同v2
-  v4: v4需要创建一个bin文件夹，并且把static文件夹放在bin文件夹下面，然后去bin文件夹下面运行./rpc_server 和./rpc_client
    > ```shell
    >     > ```shell
    > mkdir build 
    > cd build 
    > cmake .. 
    > make 
    > cd ../bin
    > ./rpc_client
    > ./rpc_server
    > ```
-  v5:
## config文件需要自己创建，按照自己的需求进行创建
###  OSS_config.json
> ```json
> {
>     "endpoint": "",
>     "accessKeyId": "",
>     "accessKeySecret":""
> }
> ```

### RabbitMQ_config.json
> ```json
> {
>     "host":"",
>     "port":,
>     "username":"",
>     "password":"",
>     "vhost":"",
>     "exchange":"",
>     "routing_key" :"",
>     "uri":"",
>     "queue":""
> }
> ```
> // uri 参考： amqp://guest:guest@localhost:5672/%2f