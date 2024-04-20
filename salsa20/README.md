## Salsa20/XSalsa20 -- stream cipher encryption

Salsa20 is a stream cipher based on a symmetric **256-Bit key**, a **64-bit** (or **192-bit for XSalsa20**) **nonce** and a **64-bit counter**. the plaintext can have a variable size. 
The parameters key, nonce and counter can be adjusted at runtime (using **rekey()** and/or **set_counter()**).

### Examples -- Salsa20
```v
import v_crypto.salsa20
import encoding.hex

fn main(){
    key := hex.decode('0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D')!
    nonce := hex.decode('0D74DB42A91077DE')!
    plain := hex.decode('766572792073686f7274206d7367')! // very short msg

     // short way to encrypt the given string `plain` using key and nonce
    println("`very short msg` encrypted with Salsa20 is: " + salsa20.encrypt(key, nonce, plain)!) // >>> 839fa746598ab737b6da80bd9efd <<<

    ciphertext := 'some-ciphertext'.bytes()

    // decrypt a string `ciphertext` with a given key, nonce, a different counter and number of Salsa20 rounds
    mut dec := []u8{len: plain4.len}
    mut c := new_cipher(key, nonce)!
    // if only the counter should be different
    // c.set_counter(45)
    c.rekey(key, nonce, 45, 8)! // key, nonce, counter, rounds
    c.xor_key_stream(mut dec, ciphertext)
    println("The decrypted ciphertext with initial counter 48 and 8 rounds is:" +dec.hex())
}
```

### Examples -- XSalsa20
```v
import v_crypto.salsa20
import encoding.hex

fn main(){
    key := hex.decode('0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D')!
    nonce := hex.decode('404142434445464748494a4b4c4d4e4f5051525354555658')! // XSalsa20 has a larger Nonce
    plain := hex.decode('766572792073686f7274206d7367')! // very short msg
    
    // short way to encrypt the given string `plain` using key and nonce
    println("`very short msg` encrypted with XSalsa20 is: " + salsa20.encrypt(key, nonce, plain)!) // >>> d0df8be036e7d95728040244ef2f <<<

    ciphertext := 'some-ciphertext'.bytes()

    // decrypt a string `ciphertext` with a given key, nonce, a different counter and number of Salsa20 rounds
    mut dec := []u8{len: plain4.len}
    mut c := new_cipher(key, nonce)!
    c.rekey(key, nonce, 45, 8)! // key, nonce, counter, rounds
    c.xor_key_stream(mut dec, ciphertext)
    println("The decrypted ciphertext with initial counter 48 and 8 rounds is:" +dec.hex())
}
```