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
Benchmark_Workflow-2                 548           2110716 ns/op           69969 B/op       1029 allocs/op
Benchmark_Negotiation-2             4640            220503 ns/op            7340 B/op        145 allocs/op
Benchmark_Encryption-2              2865            408513 ns/op           19660 B/op        265 allocs/op
Benchmark_Decryption-2              1564            810571 ns/op           26523 B/op        364 allocs/op
Benchmark_DecryptionOnR-2           2457            467090 ns/op            6681 B/op        116 allocs/op
Benchmark_DecryptionWrong-2         4022            324626 ns/op           13569 B/op        208 allocs/op
Benchmark_Update-2                  2120            574287 ns/op           15951 B/op        249 allocs/op
PASS
ok      command-line-arguments  8.941s

Encryption = Encryption

Decryption = Decryption

Decryption(Wrong) = DecryptionWrong

## 18phe

goos: linux
goarch: amd64
cpu: Intel(R) Xeon(R) Platinum 8369B CPU @ 2.70GHz
Benchmark_Workflow-2                 302           4099556 ns/op          221379 B/op       3152 allocs/op
Benchmark_RequestPublicKey-2        7387            163357 ns/op            8096 B/op        148 allocs/op
Benchmark_ZkAtEnc-2                 2432            509974 ns/op           37902 B/op        519 allocs/op
Benchmark_GetEnrollment-2           2070            553561 ns/op            7682 B/op        123 allocs/op
Benchmark_EnrollAccount-2           1407            819799 ns/op           74445 B/op       1010 allocs/op
Benchmark_Verify-2                  1574            810116 ns/op           21056 B/op        315 allocs/op
Benchmark_VerifyOnR-2               2298            566790 ns/op            6959 B/op        119 allocs/op
Benchmark_DecryptWrong-2             873           1456376 ns/op           73734 B/op       1022 allocs/op
Benchmark_CheckAndDecrypt-2         1507            845797 ns/op           69367 B/op        942 allocs/op
Benchmark_Update-2                  1748            730160 ns/op           42546 B/op        637 allocs/op
PASS
ok      command-line-arguments  15.461s

加密零知识占总加密时间：486901 / 557149 + 760433 = 36.954133%

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

+ Encryption: 3146.14 req/s
+ Decryption-Wrong: 3057.07 req/s
+ Decryption-Right: 1975.13 req/s

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





