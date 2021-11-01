## ours-sgx

server：2 core 4GiB

processor: Intel Xeon(Ice Lake) Platinum 8369B

Workflow 		720.413µs

Negotiation 	326.006µs

Encryption 	 7.2us

Validation	    10.4µs

Decryption	   370.407µs

Retrieval     	 6.4µs

Encryption = Negotiation + Encryption = 333.206 us

Decrypt-Success = Validation + Decryption + Retrieval = 387.207us

Decrypt-Wrong = Validation + Decryption = 380.807us

| 记录数量 | 时间     |
| -------- | -------- |
| 1        | 357.206  |
| 10       | 452.408  |
| 20       | 543.21   |
| 50       | 732.814  |
| 100      | 998.419  |
| 200      | 1523.629 |
| 500      | 2958.857 |
| 1000     | 5177.299 |



## 18phe

goos: linux
goarch: amd64
cpu: Intel(R) Xeon(R) Platinum 8369B CPU @ 2.70GHz
Benchmark_Workflow-2           	     302	   3926711 ns/op	  222003 B/op	    3163 allocs/op
Benchmark_RequestPublicKey-2   	    7646	    155650 ns/op	    8135 B/op	     149 allocs/op
Benchmark_ZkAtEnc-2            	    2761	    485366 ns/op	   37870 B/op	     518 allocs/op
Benchmark_GetEnrollment-2      	    2049	    541819 ns/op	    7676 B/op	     123 allocs/op
Benchmark_EnrollAccount-2      	    1466	    843656 ns/op	   74601 B/op	    1015 allocs/op
Benchmark_Verify-2             	    1677	    754890 ns/op	   21093 B/op	     315 allocs/op
Benchmark_CheckAndDecrypt-2    	    1510	    834770 ns/op	   70961 B/op	     960 allocs/op
Benchmark_Update-2             	    1920	    663746 ns/op	   40737 B/op	     616 allocs/op

加密过程中零知识占总加密过程比：485366 /  541819 +  843656 = 35.03%

加密过程中零知识占全过程比：485366 /  2975135= 16.31%

解密过程中零知识占比：（754890+834770） / 2975135 = 53.43%

## ours

goos: linux
goarch: amd64
cpu: Intel(R) Xeon(R) Platinum 8369B CPU @ 2.70GHz
Benchmark_Workflow-2      	     614	   1875984 ns/op	   76235 B/op	    1107 allocs/op
Benchmark_Negotiation-2   	    4941	    213325 ns/op	    7329 B/op	     144 allocs/op
Benchmark_Encryption-2    	    3936	    314126 ns/op	   19385 B/op	     261 allocs/op
Benchmark_Decryption-2    	    1540	    788199 ns/op	   33517 B/op	     454 allocs/op
Benchmark_Update-2        	    2157	    565333 ns/op	   15963 B/op	     249 allocs/op

