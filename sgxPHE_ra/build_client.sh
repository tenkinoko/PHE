CGO_CFLAGS=-I/opt/ego/include CGO_LDFLAGS=-L/opt/ego/lib go build sgx_client/client.go
./client -s `ego signerid public.pem`