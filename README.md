一个简单到不能再简单的https解析器

## 介绍有待完善
利用中间人攻击完成

## 不安装自签证书情况下用下面方式
http --proxy=https:http://127.0.0.1:3000 https://www.google.com.hk --verify=no

** `http` 命令需要预装 `httpie`， `brew install httpie` **

bytejump是我自签发的域名
![image](https://user-images.githubusercontent.com/24750337/90953446-3d24a980-e49e-11ea-81f3-12fe0a0415d1.png)

tls1.3 证书信息在 change spec之后就加密了，需要配置
https://www.jianshu.com/p/9c027c580f8d