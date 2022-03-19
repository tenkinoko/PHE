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

## EGO安装

1. 前置需要安装edgelessrt，推荐国内同学去github下载最近的release后按照如下安装，避免wget太慢

   ```sh
   wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add
   sudo add-apt-repository "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu `lsb_release -cs` main"
   # 下载最新版本
   # wget https://github.com/edgelesssys/edgelessrt/releases/download/v0.2.7/edgelessrt_0.2.7_amd64.deb
   sudo apt install ./edgelessrt_0.2.7_amd64.deb build-essential libssl-dev
   sudo snap install cmake --classic
   ```

2. 安装ego，同1，下载最新release

   ```bash
   wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add
   sudo add-apt-repository "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu `lsb_release -cs` main"
   # wget https://github.com/edgelesssys/ego/releases/download/v0.4.2/ego_0.4.2_amd64.deb
   sudo apt install ./ego_0.4.2_amd64.deb build-essential libssl-dev
   ```

## sgx配置与运行-以阿里云为例

1. 首先安装sgx driver和pccs（为了进行remote attestation）[Remote attestation (edgeless.systems)](https://docs.edgeless.systems/ego/#/reference/attest)

   ```bash
   sudo ego install sgx-driver
   sudo ego install libsgx-dcap-default-qpl
   ```

2. 按照[构建SGX加密计算环境 (alibabacloud.com)](https://www.alibabacloud.com/help/zh/doc-detail/208095.htm#step-fn4-02q-tj4)配置/etc/sgx_default_qcnl.conf

   ```
   # PCCS server address
   PCCS_URL=https://sgx-dcap-server.[Region-ID].aliyuncs.com/sgx/certification/v3/
   # To accept insecure HTTPS cert, set this option to FALSE
   USE_SECURE_CERT=TRUE
   ```

3. 每次进行测试和运行代码前（client和server都要）source一下

   ```
   . /opt/edgelessrt/share/openenclave/openenclaverc
   ```

4. 后按照ego sample中的remote attestation进行操作

   ```sh
   # server
   ego-go build
   ego sign server
   ego run server
   # client
   CGO_CFLAGS=-I/opt/ego/include CGO_LDFLAGS=-L/opt/ego/lib go build ra_client/client.go
   ./client -s `ego signerid public.pem`
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

