// Based on: https://github.com/karlmcguire/ige

// Infinite Garble Extension mode.
//
// See: www.links.org/files/openssl-ige.pdf
module cipher_

import crypto.cipher
import crypto.internal.subtle

struct Ige {
mut:
	b          cipher.Block
	out        []u8
	iv         []u8
	block_size int
}

// free the resources taken by the Ige `x`
@[unsafe]
pub fn (mut x Ige) free() {
	$if prealloc {
		return
	}
	unsafe {
		x.iv.free()
		x.out.free()
	}
}

// new_ige returns a Ige which encrypts/decrypts using the given Block in Infinite Garble Extension.
// iv must contain two IV's which will be split internal.
pub fn new_ige(b cipher.Block, iv []u8) !Ige {
	if iv.len != b.block_size * 2 {
		return error('v_crypto/cipher_: IV must be: (block size * 2) ${b.block_size * 2} != ${iv.len}')
	}

	return Ige{
		b: b
		out: []u8{len: b.block_size}
		iv: iv.clone()
		block_size: b.block_size
	}
}

pub fn (mut c Ige) block_size() int {
	return c.b.block_size
}

pub fn (mut c Ige) encrypt_blocks(mut dst []u8, src []u8) {
	if src.len % c.b.block_size != 0 {
		panic('v_crypto/cipher_: src not full blocks')
	}
	if dst.len < src.len {
		panic('v_crypto/cipher_: dst.len < src.len')
	}
	if subtle.inexact_overlap(dst[..src.len], src) {
		panic('crypto.cipher: invalid buffer overlap')
	}

	b := c.b.block_size
	mut l := c.iv[..b].clone()
	mut r := c.iv[b..].clone()

	for i := 0; i < src.len; i += b {
		cipher.xor_bytes(mut dst[i..i + b], src[i..i + b], l)
		c.b.encrypt(mut dst[i..i + b], dst[i..i + b])
		cipher.xor_bytes(mut dst[i..i + b], dst[i..i + b], r)

		l = dst[i..i + b].clone()
		r = src[i..i + b].clone()
	}
}

pub fn (mut c Ige) decrypt_blocks(mut dst []u8, src []u8) {
	if src.len % c.b.block_size != 0 {
		panic('v_crypto/cipher_: src not full blocks')
	}
	if dst.len < src.len {
		panic('v_crypto/cipher_: dst.len < src.len')
	}
	if subtle.inexact_overlap(dst[..src.len], src) {
		panic('crypto.cipher: invalid buffer overlap')
	}

	b := c.b.block_size
	mut l := c.iv[..b].clone()
	mut r := c.iv[b..].clone()

	for i := 0; i < src.len; i += b {
		//t := src[i..i + b]
		cipher.xor_bytes(mut dst[i..i + b], src[i..i + b], r)
		c.b.decrypt(mut dst[i..i + b], dst[i..i + b])
		cipher.xor_bytes(mut dst[i..i + b], dst[i..i + b], l)

		r = dst[i..i + b].clone()
		l = src[i..i + b].clone()
	}
}
