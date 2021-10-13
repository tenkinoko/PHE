

# Info

ns/op: nanosecond(s) per operation

B/op: bytes allocated per operation

allocs/op: how many distinct memory allocations occurred per operation

# OURS

goos: windows
goarch: amd64
pkg: virgil-phe-go
cpu: AMD Ryzen 9 5900X 12-Core Processor            
BenchmarkEnrolling
BenchmarkEnrolling-24          	 1551001	       753.5 ns/op	    1120 B/op	      28 allocs/op
BenchmarkEncryption
BenchmarkEncryption-24         	   12753	     94030 ns/op	    3091 B/op	      58 allocs/op
BenchmarkDecryption
BenchmarkDecryption-24         	   14854	     80594 ns/op	    8552 B/op	     126 allocs/op
Benchmark_proofOfSuccess
Benchmark_proofOfSuccess-24    	    4892	    246866 ns/op	   16175 B/op	     191 allocs/op
PASS

TOTAL = Enrolling + Encryption + Decryption + proofOfSuccess = 422243 ns/op

# 18 LAI

goos: windows
goarch: amd64
pkg: virgil-phe-go
cpu: AMD Ryzen 9 5900X 12-Core Processor            
BenchmarkAddP256
BenchmarkAddP256-24                               	  244218	      4978 ns/op	    3747 B/op	      52 allocs/op
BenchmarkServer_GetEnrollment
BenchmarkServer_GetEnrollment-24                  	    4438	    262533 ns/op	   19172 B/op	     259 allocs/op
BenchmarkClient_EnrollAccount
BenchmarkClient_EnrollAccount-24                  	    1933	    625538 ns/op	   73201 B/op	     998 allocs/op
BenchmarkClient_CreateVerifyPasswordRequest
BenchmarkClient_CreateVerifyPasswordRequest-24    	   10000	    105051 ns/op	   14094 B/op	     193 allocs/op
BenchmarkVerifyDecrypt
BenchmarkVerifyDecrypt-24                         	    2031	    596834 ns/op	   67115 B/op	     919 allocs/op
BenchmarkLoginFlow
BenchmarkLoginFlow-24                             	    1192	    993829 ns/op	  102942 B/op	    1404 allocs/op
PASS

TOTAL = Server_GetEnrollment + Client_EnrollAccount + Client_CreateVerifyPasswordRequest + VerifyDecrypt = 1562956 ns/op

 