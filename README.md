# Kyber (research fork)

This repository is a fork of the upstream Kyber implementation (pq-crystals/kyber), customized for post-quantum cryptography (PQC) research and benchmarking.

It contains:
- `ref/`: portable reference C implementation (clean, not platform-optimized)
- `avx2/`: optimized x86_64 implementation using AVX2/BMI2/POPCNT
- `ref/test/`: additional Kyber TCP client/server demo + stress tool (POSIX)

For a list of changes in this fork, see [CHANGELOG.md](CHANGELOG.md).

## Table of contents

- [Reproducibility quick start](#reproducibility-quick-start)
- [Build](#build)
- [Correctness tests](#correctness-tests)
- [Benchmarking (cycle counts)](#benchmarking-cycle-counts)
- [Deterministic test vectors](#deterministic-test-vectors)
- [NIST KAT generator (optional)](#nist-kat-generator-optional)
- [TCP client/server demo (optional)](#tcp-clientserver-demo-optional)
- [Coverage (optional)](#coverage-optional)
- [License](#license)

## Reproducibility quick start

### Platform notes

- **Linux is recommended** for reproducible benchmarking.
- **macOS** builds the `ref/` implementation fine in most setups.
- **Windows**: use **WSL2** (the demo tools under `ref/test/` use POSIX headers/APIs such as `unistd.h` and `fork()`).

### Dependencies

Ubuntu/Debian:

```sh
sudo apt-get update
sudo apt-get install -y build-essential make pkg-config libssl-dev
```

Optional tools:

```sh
sudo apt-get install -y valgrind lcov
```

macOS (OpenSSL headers/libs may require flags):

```sh
brew install openssl
export CFLAGS="-I$(brew --prefix openssl)/include"
export NISTFLAGS="-I$(brew --prefix openssl)/include"
export LDFLAGS="-L$(brew --prefix openssl)/lib"
```

## Build

All commands below assume you are at the repository root.

### Reference implementation (`ref/`)

Build correctness tests:

```sh
make -C ref clean
make -C ref
```

This produces:

- `ref/test/test_kyber512`
- `ref/test/test_kyber768`
- `ref/test/test_kyber1024`

### AVX2 implementation (`avx2/`)

Requires an x86_64 CPU with AVX2.

```sh
make -C avx2 clean
make -C avx2
```

This produces:

- `avx2/test/test_kyber512`, `avx2/test/test_vectors512`, `avx2/test/test_speed512`
- `avx2/test/test_kyber768`, `avx2/test/test_vectors768`, `avx2/test/test_speed768`
- `avx2/test/test_kyber1024`, `avx2/test/test_vectors1024`, `avx2/test/test_speed1024`

## Correctness tests

Reference:

```sh
./ref/test/test_kyber512
./ref/test/test_kyber768
./ref/test/test_kyber1024
```

AVX2:

```sh
./avx2/test/test_kyber512
./avx2/test/test_kyber768
./avx2/test/test_kyber1024
```

## Benchmarking (cycle counts)

The `test_speed*` programs print median and average cycle counts (1000 iterations) using `RDTSC` by default.

Reference:

```sh
make -C ref speed
./ref/test/test_speed512
./ref/test/test_speed768
./ref/test/test_speed1024
```

AVX2:

```sh
make -C avx2 speed
./avx2/test/test_speed512
./avx2/test/test_speed768
./avx2/test/test_speed1024
```

Optional (use RDPMC instead of TSC, if supported in your environment):

```sh
make -C ref clean
make -C ref speed CFLAGS="-DUSE_RDPMC"
```

Reproducibility tips:

- Pin the exact commit hash: `git rev-parse HEAD`
- Record compiler versions: `gcc --version` / `clang --version`
- Record CPU model and frequency scaling settings (e.g., `lscpu`)

## Deterministic test vectors

The `test_vectors*` programs generate deterministic test vectors (10000 sets). Randomness is derived from SHAKE128 on empty input (deterministic).

Reference (note: vector binaries are **not** built by default in `ref/`):

```sh
make -C ref test/test_vectors512 test/test_vectors768 test/test_vectors1024
./ref/test/test_vectors512 > tvecs512.txt
./ref/test/test_vectors768 > tvecs768.txt
./ref/test/test_vectors1024 > tvecs1024.txt
```

AVX2:

```sh
./avx2/test/test_vectors512 > tvecs512.txt
./avx2/test/test_vectors768 > tvecs768.txt
./avx2/test/test_vectors1024 > tvecs1024.txt
```

## NIST KAT generator (optional)

The NIST KAT generator (under `ref/nistkat/`) requires OpenSSL.

```sh
make -C ref nistkat
./ref/nistkat/PQCgenKAT_kem512
./ref/nistkat/PQCgenKAT_kem768
./ref/nistkat/PQCgenKAT_kem1024
```

The repository also includes pre-generated KAT files under `Kyber_KAT/`.

## TCP client/server demo (optional)

This fork includes a TCP socket-based client/server demonstration of Kyber KEM under `ref/test/`.

### Programs

Built binaries (per mode):

- `test_kyber_keygen{2,3,4}`: generate keypairs and write `*.bin`
- `test_kyber_server{2,3,4}`: listen on TCP port 5000, encapsulate, verify shared secret
- `test_kyber_client{2,3,4}`: connect to server, decapsulate, send shared secret for verification
- `test_kyber_stress{2,3,4}`: concurrent client load generator (uses `fork()`)

Mode mapping:

| Mode suffix | Kyber parameter set |
|-----------:|----------------------|
| 2 | Kyber512 (KYBER_K=2) |
| 3 | Kyber768 (KYBER_K=3) |
| 4 | Kyber1024 (KYBER_K=4) |

Key/ciphertext sizes:

| Set | PK | SK | CT | SS |
|-----|----:|----:|----:|----:|
| Kyber512 | 800 | 1632 | 768 | 32 |
| Kyber768 | 1184 | 2400 | 1088 | 32 |
| Kyber1024 | 1568 | 3168 | 1568 | 32 |

### Build

```sh
make -C ref/test clean
make -C ref/test all
```

### Run (localhost)

Terminal 1 (generate key files):

```sh
cd ref/test
./test_kyber_keygen2
```

Terminal 2 (server):

```sh
cd ref/test
./test_kyber_server2
```

Terminal 3 (client):

```sh
cd ref/test
./test_kyber_client2 127.0.0.1
```

Notes:

- The client accepts **only one CLI argument**: `server_ip`. The port is currently fixed to `5000` in source.
- Logs are written in the current directory:
  - client: `client_kyber.log` (override via `CLIENT_LOG_PATH=/path/to/log`)
  - server: `server_kyber.log`

### Makefile shortcuts (recommended)

Instead of calling binaries directly, you can use the helper targets in `ref/test/Makefile`:

```sh
make -C ref/test keygen MODE=2
make -C ref/test run-server MODE=2
make -C ref/test run-client MODE=2 TARGET_IP=127.0.0.1
```

### Files and logs

Generated files (in the working directory, typically `ref/test/`):

- Key material: `client_pk.bin`, `client_sk.bin`, `server_pk.bin`, `server_sk.bin`
- Logs: `client_kyber.log`, `server_kyber.log`

Log line format (one line per run):

```
status=<int>,ss_len=<bytes>,elapsed_us=<us>,user_ms=<ms>,sys_ms=<ms>,rss_kb=<kb>
```

### Error codes

Client (`test_kyber_client*`) status codes:

- `0`: success (shared secret verified)
- `-1`: send client PK failed
- `-2`: receive ciphertext failed
- `-3`: ciphertext size mismatch
- `-4`: decapsulation failed
- `-5`: send shared secret failed
- `-6`: receive verification result failed
- `-7`: verification failed (shared secret mismatch)
- `-8`: invalid verification result

Server (`test_kyber_server*`) status codes:

- `0`: success (shared secrets match)
- `1`: shared secret mismatch
- negative values: stage-specific transport/protocol errors (logged to `server_kyber.log`)

### Network protocol

Messages are framed as `uint32_be length` followed by payload:

1. client → server: client public key
2. server → client: ciphertext
3. client → server: shared secret (from decapsulation)
4. server → client: 1-byte verification result (0 = match, 1 = mismatch)

### Remote run (two machines)

The demo binaries expect key files in the working directory.

1) Run keygen once (on either machine):

```sh
cd ref/test
./test_kyber_keygen2
```

2) Copy files:

- To the server machine: `client_pk.bin`, `server_sk.bin`
- To the client machine: `client_sk.bin`, `server_pk.bin`

3) Start server on server machine:

```sh
cd ref/test
./test_kyber_server2
```

4) Run client on client machine:

```sh
cd ref/test
./test_kyber_client2 <server_ip>
```

### Stress tool

The stress tool spawns multiple concurrent client sessions and logs a line per child process.

```sh
cd ref/test
TARGET_IP=<server_ip> CONCURRENT_SESSIONS=10 CLIENT_LOG_PATH=client_stress.log ./test_kyber_stress2
```

### Troubleshooting

- `connect() failed: Connection refused`: start the server first, and check the server IP.
- `bind: Address already in use`: port `5000` is occupied; stop the other process or change `SERVER_PORT` in source.
- `Failed to open client_sk.bin` / `client_pk.bin` / `server_sk.bin` / `server_pk.bin`: run keygen and ensure you run binaries from the directory containing the `*.bin` files.

## Coverage (optional)

Generate an lcov report for the `ref/` implementation:

```sh
./runlcov.sh
```

## License

Same as the upstream Kyber reference implementation (public domain).

