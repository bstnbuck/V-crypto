// Module xtea implements XTEA encryption, as defined in Needham and Wheeler's
// 1997 technical report, "Tea extensions."
//
// XTEA is a legacy cipher and its short block size makes it vulnerable to
// birthday bound attacks (see https://sweet32.info). It should only be used
// where compatibility with legacy systems, not security, is the goal.
//
// Deprecated: any new system should use AES (from crypto/aes, if necessary in
// an AEAD mode (like GCM)) or ChaCha20-Poly1305 (x/crypto/chacha20poly1305).
//
// Based off: https://github.com/golang/crypto/blob/master/xtea/cipher.go
//

module xtea

import crypto.cipher

const block_size = 8

struct Xtea {
	block_size int = xtea.block_size
mut:
	table []u32
}

// new creates and returns a new Cipher. The key argument should be the XTEA key. XTEA only supports 128 bit (16 byte) keys.
pub fn new(key []u8) !cipher.Block {
	$if prod {
		println('XTEA is a legacy and insecure block cipher and should not be used in production environments.')
	}

	if key.len != 16 {
		return error('v_crypto/xtea: invalid key size: ${key.len}')
	}

	mut x := Xtea{}
	x.table = []u32{len: 64}
	x.init(key)
	return x
}

pub fn (x &Xtea) block_size() int {
	return xtea.block_size
}

// init initializes the cipher context by creating a look up table of precalculated values that are based on the key.
fn (mut x Xtea) init(key []u8) {
	mut k := []u32{len: 4}
	for i := 0; i < k.len; i++ {
		j := i << 2 // multiply by 4
		k[i] = u32(key[j + 0]) << 24 | u32(key[j + 1]) << 16 | u32(key[j + 2]) << 8 | u32(key[j + 3])
	}

	// precalculate table
	delta := u32(0x9E3779B9)
	mut sum := u32(0)

	// Two rounds of XTEA applied per loop
	for i := 0; i < num_rounds; {
		x.table[i] = sum + k[sum & 3]
		i++
		sum += delta
		x.table[i] = sum + k[(sum >> 11) & 3]
		i++
	}
}

// encrypt encrypts the 8 byte buffer src using the key and stores the result in dst. Note that for amounts of data larger than a block, it is not safe to just call Encrypt on successive blocks; instead, use an encryption mode like CBC (see crypto/cipher/cbc.v).
pub fn (x &Xtea) encrypt(mut dst []u8, src []u8) {
	x.encrypt_block(mut dst, src)
}

// decrypt decrypts the 8 byte buffer src using the key and stores the result in dst.
pub fn (x &Xtea) decrypt(mut dst []u8, src []u8) {
	x.decrypt_block(mut dst, src)
}
