# Time Delay (10000 iterations for sgxPHE / go bench for others)

## sgxPHE

+ Negotiation 370.407µs 

+ Encryption 10.8µs

+ validation 9.6µs 

+ Decryption 365.607µs 

+ Retrieval 7.2µs 

+ Update 397.607µs 

+ Workflow 763.614µs

Encryption = Negotiation + Encryption

Decryption = Validation + Decryption + Retrieval

## asymPHE

goos: linux
goarch: amd64
cpu: Intel(R) Xeon(R) Platinum 8369B CPU @ 2.70GHz
Benchmark_Workflow-2                 578           1929012 ns/op           76283 B/op       1107 allocs/op
Benchmark_Negotiation-2             4735            215322 ns/op            7336 B/op        144 allocs/op
Benchmark_Encryption-2              3836            313756 ns/op           19383 B/op        261 allocs/op
Benchmark_Decryption-2              1512            794724 ns/op           33382 B/op        453 allocs/op
Benchmark_DecryptionWrong-2         4162            303782 ns/op           20288 B/op        275 allocs/op
Benchmark_Update-2                  2143            558849 ns/op           15958 B/op        249 allocs/op
PASS
ok      command-line-arguments  7.557s

Encryption = Encryption

Decryption = Decryption

Decryption(Wrong) = DecryptionWrong

## 18phe

goos: linux
goarch: amd64
cpu: Intel(R) Xeon(R) Platinum 8369B CPU @ 2.70GHz
Benchmark_Workflow-2                 303           3954575 ns/op          221409 B/op       3152 allocs/op
Benchmark_RequestPublicKey-2        7629            158158 ns/op            8098 B/op        148 allocs/op
Benchmark_ZkAtEnc-2                 2749            486901 ns/op           37806 B/op        519 allocs/op
Benchmark_GetEnrollment-2           2040            557149 ns/op            7672 B/op        123 allocs/op
Benchmark_EnrollAccount-2           1575            760433 ns/op           72775 B/op        989 allocs/op
Benchmark_Verify-2                  1520            769360 ns/op           20998 B/op        314 allocs/op
Benchmark_DecryptWrong-2             847           1457483 ns/op           73612 B/op       1022 allocs/op
Benchmark_CheckAndDecrypt-2         1458            807731 ns/op           68887 B/op        936 allocs/op
Benchmark_Update-2                  1902            711640 ns/op           42556 B/op        637 allocs/op
PASS
ok      command-line-arguments  13.019s

Encryption = GetEnrollment + EnrollAccount

Decryption = Verify + CheckAndDecrypt

Decryption(Wrong) = DecryptWrong

# Throughput (10000 iterations 400 parallel requests)

### TOOL

**ghz** is a command line utility and [Go](http://golang.org/) package for load testing and benchmarking [gRPC](http://grpc.io/) services. It is intended to be used for testing and debugging services locally, and in automated continous intergration environments for performance regression testing.

## sgxPHE

+ Encryption: 3567.54 req/s
+ Decryption: 3588.62 req/s

## asymPHE

+ Encryption: 4207.41 req/s
+ Decryption-Wrong: 4407.97 req/s
+ Decryption-Right: 2434.61 req/s

## 18phe

+ Encryption: 1747.86 req/s
+ Decryption-Wrong: 1439.30 req/s
+ Decryption-Right: 1754.75 req/s

# Update Records

## sgxPHE

+ 1 record: 380.807µs + 2.35s
+ 1000 records：5.272101ms + 2.343s
+ 10000 records: 48.180ms + 2.361s
+ 100000 records: 4780.892ms + 2.346s

## asymPHE

+ 1 record: 579.552µs
+ 1000 records: 18.935880ms
+ 10000 records:  181.675820ms
+ 100000 records: 1.802376772s

## 18phe

+ 1 record: 711.640µs
+ 1000 records: 364.316916ms
+ 10000 records: 3.375648854s
+ 100000 records:  36.430650121s





