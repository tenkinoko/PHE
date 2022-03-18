## golang环境安装

```bash
sudo apt-get upgrade
sudo apt-get update
sudo apt-get install golang-go
go version
```

## SGX支持（阿里云ubuntu 20 c7t实例）

```bash
bash /auto_install_sgx.sh
sudo apt-get install cpuid
cpuid | grep "SGX"
```

## golang初始化

```bash
go env -w GOPROXY=https://goproxy.cn,direct # 开启代理
go mod tidy
go mod verify
```

## time delay

```bash
go test -v -bench=. test/server_test.go
# 在utils/utils.go中更改相关参数进行性能测试
go test -v -bench=. test/client_test.go
```

## 吞吐量

```
go run ghz/ghz.go
```

1. 修改ghz.go 中的item
2. 修改runner中的method
3. runner参数修改
4. 检查utils.go中的参数

