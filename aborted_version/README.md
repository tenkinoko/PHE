## Ref

[Go和HTTPS - Go语言中文网 - Golang中文社区 (studygolang.com)](https://studygolang.com/articles/9267)

## 使用开启扩展SAN的证书

```shell
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -days 5000 -out ca.crt
openssl genrsa -out server.key 2048
openssl req -new -sha256 -out server.csr -key server.key -config server.conf
openssl x509 -req -days 3650 -CA ca.crt -CAkey ca.key -CAcreateserial -in server.csr -out server.crt -extensions req_ext -extfile server.cfg
openssl req -new -key client.key -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 5000
```

