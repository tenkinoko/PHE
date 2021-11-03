# Time Delay (10000 iterations for sgx / go bench for others)

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

# Throughput (10000 iterations 400 parallel requests)

## sgxPHE

+ Encryption: 3567.54 req/s
+ Decryption: 3588.62 req/s



# Update

## sgxPHE

+ 1 record: 397.607µs + 2.428s
+ 1000 records：5423.304µs + 2.428s
+ 10000 records: 49.360ms + 2.428s
+ 100000 records: 487.689384ms + 2.428s



