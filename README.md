# go-socks5
## 使用 （假设构建后的二进制文件是 socks5Server）
* golang的版本至少为： go-1.21.0 (引入了标准库的slog)
* 目前只支持远程服务端的部署使用，本地服务端（对接远程服务端和本里浏览器等）功能有问题需要解决

``` shell
# 作为远程服务端： 不指定端口，默认10808, 不指定用户名和密码，则不需要认证; 作为服务端代理-server 必须的参数，作为本地客户端不需要
socks5Server -server -port=8090 -username=admin -passwd=123456

# 作为中转的本地服务端，是远程服务端的客户端实现； remoteAddr 填写远程服务端的ip remotePort远程服务端的端口如上面的8090
# 解决chrome和edge浏览器不支持socks5用户名密码认证的一个补充，远程服务端未开启用户名密码认证不需要启动，但确保远程服务端的安全，建议开启
# 重点：改客户端与服务端的交互有问题，暂不可使用
socks5Server -port=8080 -username=admin -passwd=123456 -remoteAddr=127.0.0.1 -remotePort=8090
```