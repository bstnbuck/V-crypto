# V-crypto :key:

> **Attention!**
**V-crypto** has no connection to the official V community and is not maintained by it. 
**&rarr; It is not recommended to use the algorithms implemented here productively.** As a non-cryptographer, I cannot fully validate the security.

---

##### V-crypto provides...
* a detailed **overview** of important cryptographic algorithms, protocols and formats,
* the **current implementation status** of the official V community. 

Less known but relevant as well as self-developed official algorithms might be published here (see `src/` folder). 

### Cryptographic algorithms and protocols available in V standard library
| algorithm | category, info | importance | status | 
| --- | --- | --- | --- |
| **AES** | symmetric block cipher | high, daily use | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/aes)]|
| **bcrypt** | hash-algorithm | high | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/bcrypt)]|
| **blake2(b,s)** | hash-algorithm | moderate | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/blake2b)] [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/blake2s)]|
| **blake3** | hash-algorithm | moderate | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/blake3)]|
| **blowfish** | legacy symmetric block cipher | moderate | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/blowfish)]|
| *blockcipher modes* &rarr; **CBC, CFB, CTR, OFB** | Cipher-Block-Chaining, Cipher-Feedback, Counter, Output-Feedback | high | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/cipher)]|
| **DES** | legacy symmetric block cipher | low | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/des)]|
| **Ed25519** | signature algorithm based on elliptic curves | high | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/ed25519)]|
| HMAC | hash-based message authentication code | high | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/hmac)]|
| **MD5** | legacy hash-algorithm | high | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/md5)]|
| PEM | encoding format | high | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/pem)]|
| **RAND** | random number generator | high, daily use | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/rand)]|
| RC4 | legacy stream cipher | low | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/rc4)]|
| **SHA1** | legacy hash-algorithm | moderate | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/sha1)]|
| **SHA256** | hash-algorithm | high, daily use | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/sha256)]|
| **SHA512** | hash-algorithm | high, daily use | implemented :heavy_check_mark: [[Git](https://github.com/vlang/v/tree/master/vlib/crypto/sha512)]|
| **ChaCha20** | symmetric stream cipher | high, daily use | experimental :yellow_circle: [[Git](https://github.com/vlang/v/tree/master/vlib/x/crypto/chacha20)]|
| **ChaCha20-Poly1305** | Authenticated encryption with associated data (AEAD) | high, daily use | experimental :yellow_circle: [[Git](https://github.com/vlang/v/tree/master/vlib/x/crypto/chacha20poly1305)]|
| Poly1305 | message authentication code | moderate | experimental :yellow_circle: [[Git](https://github.com/vlang/v/tree/master/vlib/x/crypto/poly1305)]|
| SM4 | block cipher | moderate | experimental :yellow_circle: [[Git](https://github.com/vlang/v/tree/master/vlib/x/crypto/sm4)]|

### Cryptographic algorithms and protocols (not officially) planned for V standard library

The V wrapper libsodium [[Git](https://github.com/vlang/libsodium)] has some of these algorithms.

| algorithm | category, info | importance | status |
| --- | --- | --- | --- |
| *blockcipher modes* &rarr; **XTS, CCM, GCM** | XEX-based tweaked-codebook mode with ciphertext stealing, Counter with CBC-MAC (AEAD), Galois/Counter (AEAD) | high | :x: |
| **Curve25519** | elliptic curve | high, daily use | :x: |
| **DSA** | legacy signature algorithm | low | (see [[1](https://github.com/vlang/v/discussions/12679)]) :x: |
| **ECDH** | asymmetric crypto based on elliptic curves | high, daily use | (see [[1](https://github.com/vlang/v/discussions/12679)], [[2](https://github.com/vlang/v/issues/8547)]) :x: |
| **ECDSA** | signature algorithm based on elliptic curves | high, daily use | (see [[1](https://github.com/vlang/v/discussions/12679)]) :x: |
| HKDF | key derivation function | moderate | :x: |
| **P-224/256/384**/(521) | elliptic curves (NIST) | high, daily use | :x: |
| **PBKDF2** | key derivation function | high | :x: |
| **RSA** | asymmetric crypto | high, daily use | (see [[1](https://github.com/vlang/v/discussions/12679)]), thirdparty, non standard :yellow_circle: [[Git](https://github.com/LvMalware/rsa-vlang)] [[Git](https://github.com/LvMalware/vrsa-package)] |
| **SHA3** | hash-algorithm | moderate | (see [[2](https://github.com/vlang/v/issues/8547)]) :x: |
| **SSH** | network protocol | high, daily use | (see [[2](https://github.com/vlang/v/issues/8547)]) :x: |
| **TLS** | protocol for secure network communication | high, daily use | (see [[2](https://github.com/vlang/v/issues/8547)]), wrapper, thirdparty :yellow_circle: [[Git](https://github.com/vlang/v/tree/master/thirdparty/mbedtls)]|
| x509 | encoding format | high | wrapper, thirdparty :yellow_circle: [[Git](https://github.com/vlang/v/tree/master/thirdparty/mbedtls)] |

### Additional cryptographic algorithms implemented/planned in V-crypto (see `src/`)

The V wrapper libsodium [[Git](https://github.com/vlang/libsodium)] has some of these algorithms.

| algorithm | category, info | importance | status | 
| --- | --- | --- | --- |
| **argon2** | hash-algorithm / key derivation function | high | :x: |
| *blockcipher modes* &rarr; ECB, EAX, IGE | Electronic-Codebook, encrypt-then-authenticate-then-translate, Infinite Garble Extension | moderate | :x: |
| **brainpoolP(256,384,521)r1** | elliptic curve | high | :x: |
| Camellia | symmetric block cipher | low | :x: |
| CAST | symmetric block cipher | moderate | :x: |
| **Curve448** | elliptic curve | high | :x: |
| **Ed448** | signature algorithm based on asymmetric crypto | high | :x: |
| Kyber(512,1024) | key encapsulation mechanism, post-quanten crypto | low | :x: |
| MD4 | legacy hash-algorithm | low | :x: |
| **RIPEMD160** | hash-algorithm | moderate | :x: |
| **Salsa20** | symmetric stream cipher | high | :x: |
| **scrypt** | hash-algorithm / key derivation function | high | :x: |
| TEA | legacy block cipher | low | :x: |
| **Twofisch** | symmetric block cipher | moderate | :x: |
| **yescrypt** | hash-algorithm / key derivation function | high | :x: |

> Last Update: 16-02-2024