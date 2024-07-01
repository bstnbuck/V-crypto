// Electronic Codebook (ECB) mode.
//
// See NIST SP 800-38A, pp 9
module cipher_

import crypto.cipher

struct Ecb {
mut:
	b          cipher.Block
	out        []u8
	block_size int
}

// new_ecb returns a Ecb which encrypts/decrypts using the given Block in electronic codebook mode.
pub fn new_ecb(b cipher.Block) Ecb {
	return Ecb{
		b: b
		out: []u8{len: b.block_size}
		block_size: b.block_size
	}
}

// encrypt_blocks encrypts the blocks in `src_` to `dst_`.
// Please note: `dst` is mutable for performance reasons.
pub fn (mut x Ecb) encrypt_blocks(mut dst_ []u8, src_ []u8) {
	unsafe {
		mut src := src_
		mut dst := *dst_

		if src.len % x.block_size != 0 {
			panic('v_crypto/cipher_: input not full blocks')
		}
		if dst.len < src.len {
			panic('v_crypto/cipher_: output smaller than input')
		}

		for src.len > 0 {
			x.b.encrypt(mut dst[..x.block_size], src[..x.block_size])

			src = src[x.block_size..]
			dst = dst[x.block_size..]
		}
	}
}

// decrypt_blocks decrypts the blocks in `src` to `dst`.
// Please note: `dst` is mutable for performance reasons.
pub fn (mut x Ecb) decrypt_blocks(mut dst_ []u8, src_ []u8) {
	unsafe {
		mut src := src_
		mut dst := *dst_

		if src.len % x.block_size != 0 {
			panic('v_crypto/cipher_: input not full blocks')
		}
		if dst.len < src.len {
			panic('v_crypto/cipher_: output smaller than input')
		}

		for src.len > 0 {
			x.b.decrypt(mut dst[..x.block_size], src[..x.block_size])

			src = src[x.block_size..]
			dst = dst[x.block_size..]
		}
	}
}
