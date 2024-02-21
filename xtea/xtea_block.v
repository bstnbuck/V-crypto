// Implementation adapted from Needham and Wheeler's paper: http://www.cix.co.uk/~klockstone/xtea.pdf
// A precalculated look up table is used during encryption/decryption for values that are based purely on the key.
//
// Based off: https://github.com/golang/crypto/blob/master/xtea/block.go
//

module xtea

const num_rounds = 64

// block_to_u32 reads an 8 byte slice into two u32's. The block is treated as big endian.
fn block_to_u32(src []byte) (u32, u32) {
	r0 := u32(src[0]) << 24 | u32(src[1]) << 16 | u32(src[2]) << 8 | u32(src[3])
	r1 := u32(src[4]) << 24 | u32(src[5]) << 16 | u32(src[6]) << 8 | u32(src[7])
	return r0, r1
}

// u32_to_block writes two u32's into an 8 byte data block. Values are written as big endian.
fn u32_to_block(v0 u32, v1 u32, mut dst []u8) {
	dst[0] = u8(v0 >> 24)
	dst[1] = u8(v0 >> 16)
	dst[2] = u8(v0 >> 8)
	dst[3] = u8(v0)
	dst[4] = u8(v1 >> 24)
	dst[5] = u8(v1 >> 16)
	dst[6] = u8(v1 >> 8)
	dst[7] = u8(v1 >> 0)
}

fn (x &Xtea) encrypt_block(mut dst []u8, src []u8) {
	mut v0, mut v1 := block_to_u32(src)
	// mut v1 := block_to_u32(src)

	// Two rounds of XTEA applied per loop
	for i := 0; i < xtea.num_rounds; {
		v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ x.table[i]
		i++
		v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ x.table[i]
		i++
	}

	u32_to_block(v0, v1, mut dst)
}

fn (x &Xtea) decrypt_block(mut dst []u8, src []u8) {
	mut v0, mut v1 := block_to_u32(src)
	// mut v1 := block_to_u32(src)

	// Two rounds of XTEA applied per loop
	for i := xtea.num_rounds; i > 0; {
		i--
		v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ x.table[i]
		i--
		v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ x.table[i]
	}

	u32_to_block(v0, v1, mut dst)
}
