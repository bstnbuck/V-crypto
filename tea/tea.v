// Module tea implements the TEA algorithm, as defined in Needham and
// Wheeler's 1994 technical report, “TEA, a Tiny Encryption Algorithm”. See
// http://www.cix.co.uk/~klockstone/tea.pdf for details.
//
// TEA is a legacy cipher and its short block size makes it vulnerable to
// birthday bound attacks (see https://sweet32.info). It should only be used
// where compatibility with legacy systems, not security, is the goal.
//
// Deprecated: any new system should use AES (from crypto/aes, if necessary in
// an AEAD mode (like GCM)) or ChaCha20-Poly1305 (x/crypto/chacha20poly1305).
//
// Based off: https://github.com/golang/crypto/blob/master/tea/cipher.go
//

module tea

import crypto.cipher
import encoding.binary

pub const block_size = 8
pub const key_size = 16
const num_rounds = 64
const delta = u32(0x9e3779b9)

struct Tea {
	block_size int = tea.block_size
mut:
	key    []u8
	rounds int
}

// new_cipher returns an instance of the TEA cipher with the standard number of rounds. The key argument must be 16 bytes long.
pub fn new_cipher(key []u8) !cipher.Block {
	$if prod {
		println('TEA is a legacy and insecure block cipher and should not be used in production environments.')
	}
	return new_cipher_with_rounds(key, tea.num_rounds)!
}

// new_cipher_with_rounds returns an instance of the TEA cipher with a given number of rounds, which must be even. The key argument must be 16 bytes long.
pub fn new_cipher_with_rounds(key []u8, rounds int) !cipher.Block {
	if key.len != 16 {
		return error('v_crypto/tea: incorrect key size')
	}

	if rounds & 1 != 0 {
		return error('v_crypto/tea: odd number of rounds specified')
	}

	mut c := Tea{}
	c.key = key
	c.rounds = rounds

	return c
}

pub fn (t &Tea) block_size() int {
	return tea.block_size
}

// encrypt encrypts the 8 byte buffer src using the key in t and stores the result in dst. Note that for amounts of data larger than a block, it is not safe to just call encrypt on successive blocks; instead, use an encryption mode like CBC (see crypto/cipher/cbc.v).
pub fn (t &Tea) encrypt(mut dst []u8, src []u8) {
	mut v0 := binary.big_endian_u32(src)
	mut v1 := binary.big_endian_u32(src[4..])
	k0 := binary.big_endian_u32(t.key[0..])
	k1 := binary.big_endian_u32(t.key[4..])
	k2 := binary.big_endian_u32(t.key[8..])
	k3 := binary.big_endian_u32(t.key[12..])

	mut sum := u32(0)
	d := u32(tea.delta)

	for i := 0; i < t.rounds / 2; i++ {
		sum += d
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
	}

	binary.big_endian_put_u32(mut dst, v0)
	binary.big_endian_put_u32(mut dst[4..], v1)
}

// decrypt decrypts the 8 byte buffer src using the key in t and stores the result in dst.
pub fn (t &Tea) decrypt(mut dst []u8, src []u8) {
	mut v0 := binary.big_endian_u32(src)
	mut v1 := binary.big_endian_u32(src[4..])
	k0 := binary.big_endian_u32(t.key[0..])
	k1 := binary.big_endian_u32(t.key[4..])
	k2 := binary.big_endian_u32(t.key[8..])
	k3 := binary.big_endian_u32(t.key[12..])

	mut sum := u32(t.rounds / 2) * tea.delta
	d := u32(tea.delta)

	for i := 0; i < t.rounds / 2; i++ {
		v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
		v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
		sum -= d
	}

	binary.big_endian_put_u32(mut dst, v0)
	binary.big_endian_put_u32(mut dst[4..], v1)
}
