## 18phe

goos: windows
goarch: amd64
pkg: 18phe/test
cpu: AMD Ryzen 9 5900X 12-Core Processor            
Benchmark_Workflow
Benchmark_Workflow-24            	     411	   3260019 ns/op	  223320 B/op	    3179 allocs/op
Benchmark_RequestPublicKey
Benchmark_RequestPublicKey-24    	    1926	    663007 ns/op	    8561 B/op	     157 allocs/op
Benchmark_EnrollAccount
Benchmark_EnrollAccount-24       	    1099	   1069215 ns/op	   81041 B/op	    1124 allocs/op
Benchmark_Verify
Benchmark_Verify-24              	    2220	    502258 ns/op	   21208 B/op	     316 allocs/op
Benchmark_CheckAndDecrypt
Benchmark_CheckAndDecrypt-24     	    1815	    651988 ns/op	   71280 B/op	     962 allocs/op
Benchmark_Update
Benchmark_Update-24              	    1881	    639683 ns/op	   41137 B/op	     622 allocs/op
PASS

## ours

goos: windows
goarch: amd64
pkg: simple_phe/test
cpu: AMD Ryzen 9 5900X 12-Core Processor            
Benchmark_Workflow
Benchmark_Workflow-24       	     855	   1347672 ns/op	   77154 B/op	    1124 allocs/op
Benchmark_Negotiation
Benchmark_Negotiation-24    	    4806	    284102 ns/op	    7488 B/op	     148 allocs/op
Benchmark_Encryption
Benchmark_Encryption-24     	    2881	    509384 ns/op	   19729 B/op	     267 allocs/op
Benchmark_Decryption
Benchmark_Decryption-24     	    2179	    537891 ns/op	   33511 B/op	     455 allocs/op
Benchmark_Update
Benchmark_Update-24         	    2996	    447183 ns/op	   16084 B/op	     251 allocs/op
PASS

Process finished with the exit code 0