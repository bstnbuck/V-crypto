// Based on: https://github.com/golang/crypto/blob/master/twofish/twofish.go

// Module twofish implements Bruce Schneier's Twofish encryption algorithm.
//
// Deprecated: Twofish is a legacy cipher and should not be used for new
// applications. Instead, use AES (from crypto/aes, if necessary in an AEAD
// mode) or XChaCha20-Poly1305 (from
// /x/crypto/chacha20poly1305).
module twofish

import math.bits

// block_size is the constant block size of Twofish.
const block_size = 16

// vfmt off
const mds_polynomial = 0x169 // x^8 + x^6 + x^5 + x^3 + 1
const rs_polynomial = 0x14d // x^8 + x^6 + x^3 + x^2 + 1

// The RS matrix
const rs = [
	[u8(0x01), 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
	[u8(0xA4), 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
	[u8(0x02), 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
	[u8(0xA4), 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
	]

// sbox tables
const sbox = [
	[
		u8(0xa9), 0x67, 0xb3, 0xe8, 0x04, 0xfd, 0xa3, 0x76, 0x9a, 0x92, 0x80, 0x78, 0xe4, 0xdd, 0xd1, 0x38,
		0x0d, 0xc6, 0x35, 0x98, 0x18, 0xf7, 0xec, 0x6c, 0x43, 0x75, 0x37, 0x26, 0xfa, 0x13, 0x94, 0x48,
		0xf2, 0xd0, 0x8b, 0x30, 0x84, 0x54, 0xdf, 0x23, 0x19, 0x5b, 0x3d, 0x59, 0xf3, 0xae, 0xa2, 0x82,
		0x63, 0x01, 0x83, 0x2e, 0xd9, 0x51, 0x9b, 0x7c, 0xa6, 0xeb, 0xa5, 0xbe, 0x16, 0x0c, 0xe3, 0x61,
		0xc0, 0x8c, 0x3a, 0xf5, 0x73, 0x2c, 0x25, 0x0b, 0xbb, 0x4e, 0x89, 0x6b, 0x53, 0x6a, 0xb4, 0xf1,
		0xe1, 0xe6, 0xbd, 0x45, 0xe2, 0xf4, 0xb6, 0x66, 0xcc, 0x95, 0x03, 0x56, 0xd4, 0x1c, 0x1e, 0xd7,
		0xfb, 0xc3, 0x8e, 0xb5, 0xe9, 0xcf, 0xbf, 0xba, 0xea, 0x77, 0x39, 0xaf, 0x33, 0xc9, 0x62, 0x71,
		0x81, 0x79, 0x09, 0xad, 0x24, 0xcd, 0xf9, 0xd8, 0xe5, 0xc5, 0xb9, 0x4d, 0x44, 0x08, 0x86, 0xe7,
		0xa1, 0x1d, 0xaa, 0xed, 0x06, 0x70, 0xb2, 0xd2, 0x41, 0x7b, 0xa0, 0x11, 0x31, 0xc2, 0x27, 0x90,
		0x20, 0xf6, 0x60, 0xff, 0x96, 0x5c, 0xb1, 0xab, 0x9e, 0x9c, 0x52, 0x1b, 0x5f, 0x93, 0x0a, 0xef,
		0x91, 0x85, 0x49, 0xee, 0x2d, 0x4f, 0x8f, 0x3b, 0x47, 0x87, 0x6d, 0x46, 0xd6, 0x3e, 0x69, 0x64,
		0x2a, 0xce, 0xcb, 0x2f, 0xfc, 0x97, 0x05, 0x7a, 0xac, 0x7f, 0xd5, 0x1a, 0x4b, 0x0e, 0xa7, 0x5a,
		0x28, 0x14, 0x3f, 0x29, 0x88, 0x3c, 0x4c, 0x02, 0xb8, 0xda, 0xb0, 0x17, 0x55, 0x1f, 0x8a, 0x7d,
		0x57, 0xc7, 0x8d, 0x74, 0xb7, 0xc4, 0x9f, 0x72, 0x7e, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
		0x6e, 0x50, 0xde, 0x68, 0x65, 0xbc, 0xdb, 0xf8, 0xc8, 0xa8, 0x2b, 0x40, 0xdc, 0xfe, 0x32, 0xa4,
		0xca, 0x10, 0x21, 0xf0, 0xd3, 0x5d, 0x0f, 0x00, 0x6f, 0x9d, 0x36, 0x42, 0x4a, 0x5e, 0xc1, 0xe0,
	],
	[
		u8(0x75), 0xf3, 0xc6, 0xf4, 0xdb, 0x7b, 0xfb, 0xc8, 0x4a, 0xd3, 0xe6, 0x6b, 0x45, 0x7d, 0xe8, 0x4b,
		0xd6, 0x32, 0xd8, 0xfd, 0x37, 0x71, 0xf1, 0xe1, 0x30, 0x0f, 0xf8, 0x1b, 0x87, 0xfa, 0x06, 0x3f,
		0x5e, 0xba, 0xae, 0x5b, 0x8a, 0x00, 0xbc, 0x9d, 0x6d, 0xc1, 0xb1, 0x0e, 0x80, 0x5d, 0xd2, 0xd5,
		0xa0, 0x84, 0x07, 0x14, 0xb5, 0x90, 0x2c, 0xa3, 0xb2, 0x73, 0x4c, 0x54, 0x92, 0x74, 0x36, 0x51,
		0x38, 0xb0, 0xbd, 0x5a, 0xfc, 0x60, 0x62, 0x96, 0x6c, 0x42, 0xf7, 0x10, 0x7c, 0x28, 0x27, 0x8c,
		0x13, 0x95, 0x9c, 0xc7, 0x24, 0x46, 0x3b, 0x70, 0xca, 0xe3, 0x85, 0xcb, 0x11, 0xd0, 0x93, 0xb8,
		0xa6, 0x83, 0x20, 0xff, 0x9f, 0x77, 0xc3, 0xcc, 0x03, 0x6f, 0x08, 0xbf, 0x40, 0xe7, 0x2b, 0xe2,
		0x79, 0x0c, 0xaa, 0x82, 0x41, 0x3a, 0xea, 0xb9, 0xe4, 0x9a, 0xa4, 0x97, 0x7e, 0xda, 0x7a, 0x17,
		0x66, 0x94, 0xa1, 0x1d, 0x3d, 0xf0, 0xde, 0xb3, 0x0b, 0x72, 0xa7, 0x1c, 0xef, 0xd1, 0x53, 0x3e,
		0x8f, 0x33, 0x26, 0x5f, 0xec, 0x76, 0x2a, 0x49, 0x81, 0x88, 0xee, 0x21, 0xc4, 0x1a, 0xeb, 0xd9,
		0xc5, 0x39, 0x99, 0xcd, 0xad, 0x31, 0x8b, 0x01, 0x18, 0x23, 0xdd, 0x1f, 0x4e, 0x2d, 0xf9, 0x48,
		0x4f, 0xf2, 0x65, 0x8e, 0x78, 0x5c, 0x58, 0x19, 0x8d, 0xe5, 0x98, 0x57, 0x67, 0x7f, 0x05, 0x64,
		0xaf, 0x63, 0xb6, 0xfe, 0xf5, 0xb7, 0x3c, 0xa5, 0xce, 0xe9, 0x68, 0x44, 0xe0, 0x4d, 0x43, 0x69,
		0x29, 0x2e, 0xac, 0x15, 0x59, 0xa8, 0x0a, 0x9e, 0x6e, 0x47, 0xdf, 0x34, 0x35, 0x6a, 0xcf, 0xdc,
		0x22, 0xc9, 0xc0, 0x9b, 0x89, 0xd4, 0xed, 0xab, 0x12, 0xa2, 0x0d, 0x52, 0xbb, 0x02, 0x2f, 0xa9,
		0xd7, 0x61, 0x1e, 0xb4, 0x50, 0x04, 0xf6, 0xc2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xbe, 0x91,
	],
]

// vfmt on
struct Twofish {
mut:
	s [][]u32
	k []u32
}


// free the resources taken by the Twofish `tf`. Dont use cipher after .free call
@[unsafe]
pub fn (mut tf Twofish) free() {
	$if prealloc {
		return
	}
	unsafe {
		tf.s.free()
		tf.k.free()
	}
}

// block_size returns the Twofish block size, 16 bytes.
pub fn (mut tf Twofish) block_size() int {
	return twofish.block_size
}

// new_cipher creates and returns a new Twofish cipher.
// The key argument should be the Twofish key, 16, 24 or 32 u8s.
pub fn new_cipher(key []u8) !Twofish {
	keylen := key.len

	if keylen != 16 && keylen != 24 && keylen != 32 {
		return error('v_crypto/twofish: invalid key size ${keylen}')
	}

	// k is the number of 64 bit words in key
	k := keylen / 8

	// Create the s[..] words
	mut s := []u8{len: 4 * 4}
	for i := 0; i < k; i++ {
		// Computes [y0 y1 y2 y3] = rs . [x0 x1 x2 x3 x4 x5 x6 x7]
		for j, rs_row in twofish.rs {
			for l, rs_val in rs_row {
				s[4 * i + j] ^= gf_mult(key[8 * i + l], rs_val, twofish.rs_polynomial)
			}
		}
	}

	// Calculate subkeys
	mut tf := Twofish{}
	tf.s = [][]u32{len: 4, init: []u32{len: 256}}
	tf.k = []u32{len: 40}

	mut tmp := []u8{len: 4}
	for i := u8(0); i < 20; i++ {
		// a = h(p * 2x, Me)
		for j, _ in tmp {
			tmp[j] = 2 * i
		}
		a := h(tmp[..], key, 0)

		// b = rolc(h(p * (2x + 1), Mo), 8)
		for j, _ in tmp {
			tmp[j] = 2 * i + 1
		}
		mut b := h(tmp[..], key, 1)
		b = bits.rotate_left_32(b, 8)

		tf.k[2 * i] = a + b

		// k[2i+1] = (a + 2b) <<< 9
		tf.k[2 * i + 1] = bits.rotate_left_32(2 * b + a, 9)
	}

	// Calculate sboxes
	match k {
		2 {
			for i, _ in tf.s[0] {
				tf.s[0][i] = mds_column_mult(twofish.sbox[1][twofish.sbox[0][twofish.sbox[0][u8(i)] ^ s[0]] ^ s[4]],
					0)
				tf.s[1][i] = mds_column_mult(twofish.sbox[0][twofish.sbox[0][twofish.sbox[1][u8(i)] ^ s[1]] ^ s[5]],
					1)
				tf.s[2][i] = mds_column_mult(twofish.sbox[1][twofish.sbox[1][twofish.sbox[0][u8(i)] ^ s[2]] ^ s[6]],
					2)
				tf.s[3][i] = mds_column_mult(twofish.sbox[0][twofish.sbox[1][twofish.sbox[1][u8(i)] ^ s[3]] ^ s[7]],
					3)
			}
		}
		3 {
			for i, _ in tf.s[0] {
				tf.s[0][i] = mds_column_mult(twofish.sbox[1][twofish.sbox[0][twofish.sbox[0][twofish.sbox[1][u8(i)] ^ s[0]] ^ s[4]] ^ s[8]],
					0)
				tf.s[1][i] = mds_column_mult(twofish.sbox[0][twofish.sbox[0][twofish.sbox[1][twofish.sbox[1][u8(i)] ^ s[1]] ^ s[5]] ^ s[9]],
					1)
				tf.s[2][i] = mds_column_mult(twofish.sbox[1][twofish.sbox[1][twofish.sbox[0][twofish.sbox[0][u8(i)] ^ s[2]] ^ s[6]] ^ s[10]],
					2)
				tf.s[3][i] = mds_column_mult(twofish.sbox[0][twofish.sbox[1][twofish.sbox[1][twofish.sbox[0][u8(i)] ^ s[3]] ^ s[7]] ^ s[11]],
					3)
			}
		}
		else {
			for i, _ in tf.s[0] {
				tf.s[0][i] = mds_column_mult(twofish.sbox[1][twofish.sbox[0][twofish.sbox[0][twofish.sbox[1][twofish.sbox[1][u8(i)] ^ s[0]] ^ s[4]] ^ s[8]] ^ s[12]],
					0)
				tf.s[1][i] = mds_column_mult(twofish.sbox[0][twofish.sbox[0][twofish.sbox[1][twofish.sbox[1][twofish.sbox[0][u8(i)] ^ s[1]] ^ s[5]] ^ s[9]] ^ s[13]],
					1)
				tf.s[2][i] = mds_column_mult(twofish.sbox[1][twofish.sbox[1][twofish.sbox[0][twofish.sbox[0][twofish.sbox[0][u8(i)] ^ s[2]] ^ s[6]] ^ s[10]] ^ s[14]],
					2)
				tf.s[3][i] = mds_column_mult(twofish.sbox[0][twofish.sbox[1][twofish.sbox[1][twofish.sbox[0][twofish.sbox[1][u8(i)] ^ s[3]] ^ s[7]] ^ s[11]] ^ s[15]],
					3)
			}
		}
	}
	return tf
}

// encrypt encrypts a 16-u8 block from src to dst, which may overlap.
// Note that for amounts of data larger than a block,
// it is not safe to just call encrypt on successive blocks;
// instead, use an encryption mode like CBC (see crypto/cipher/cbc.v).
pub fn (mut tf Twofish) encrypt(mut dst []u8, src []u8) {
	s1 := tf.s[0]
	s2 := tf.s[1]
	s3 := tf.s[2]
	s4 := tf.s[3]

	// Load input
	mut ia := load32l(src[0..4])
	mut ib := load32l(src[4..8])
	mut ic := load32l(src[8..12])
	mut id := load32l(src[12..16])

	// Pre-whitening
	ia ^= tf.k[0]
	ib ^= tf.k[1]
	ic ^= tf.k[2]
	id ^= tf.k[3]

	for i := 0; i < 8; i++ {
		k := tf.k[8 + i * 4..12 + i * 4]
		mut t2 := s2[u8(ib)] ^ s3[u8(ib >> 8)] ^ s4[u8(ib >> 16)] ^ s1[u8(ib >> 24)]
		mut t1 := s1[u8(ia)] ^ s2[u8(ia >> 8)] ^ s3[u8(ia >> 16)] ^ s4[u8(ia >> 24)] + t2
		ic = bits.rotate_left_32(ic ^ (t1 + k[0]), -1)
		id = bits.rotate_left_32(id, 1) ^ (t2 + t1 + k[1])

		t2 = s2[u8(id)] ^ s3[u8(id >> 8)] ^ s4[u8(id >> 16)] ^ s1[u8(id >> 24)]
		t1 = s1[u8(ic)] ^ s2[u8(ic >> 8)] ^ s3[u8(ic >> 16)] ^ s4[u8(ic >> 24)] + t2
		ia = bits.rotate_left_32(ia ^ (t1 + k[2]), -1)
		ib = bits.rotate_left_32(ib, 1) ^ (t2 + t1 + k[3])
	}

	// Output with "undo last swap"
	ta := ic ^ tf.k[4]
	tb := id ^ tf.k[5]
	tc := ia ^ tf.k[6]
	td := ib ^ tf.k[7]

	store32l(mut dst[0..4], ta)
	store32l(mut dst[4..8], tb)
	store32l(mut dst[8..12], tc)
	store32l(mut dst[12..16], td)
}

// decrypt decrypts a 16-u8 block from src to dst, which may overlap.
pub fn (mut tf Twofish) decrypt(mut dst []u8, src []u8) {
	s1 := tf.s[0]
	s2 := tf.s[1]
	s3 := tf.s[2]
	s4 := tf.s[3]

	// Load input
	mut ta := load32l(src[0..4])
	mut tb := load32l(src[4..8])
	mut tc := load32l(src[8..12])
	mut td := load32l(src[12..16])

	// Undo undo final swap
	mut ia := tc ^ tf.k[6]
	mut ib := td ^ tf.k[7]
	mut ic := ta ^ tf.k[4]
	mut id := tb ^ tf.k[5]

	for i := 8; i > 0; i-- {
		k := tf.k[4 + i * 4..8 + i * 4]
		mut t2 := s2[u8(id)] ^ s3[u8(id >> 8)] ^ s4[u8(id >> 16)] ^ s1[u8(id >> 24)]
		mut t1 := s1[u8(ic)] ^ s2[u8(ic >> 8)] ^ s3[u8(ic >> 16)] ^ s4[u8(ic >> 24)] + t2
		ia = bits.rotate_left_32(ia, 1) ^ (t1 + k[2])
		ib = bits.rotate_left_32(ib ^ (t2 + t1 + k[3]), -1)

		t2 = s2[u8(ib)] ^ s3[u8(ib >> 8)] ^ s4[u8(ib >> 16)] ^ s1[u8(ib >> 24)]
		t1 = s1[u8(ia)] ^ s2[u8(ia >> 8)] ^ s3[u8(ia >> 16)] ^ s4[u8(ia >> 24)] + t2
		ic = bits.rotate_left_32(ic, 1) ^ (t1 + k[0])
		id = bits.rotate_left_32(id ^ (t2 + t1 + k[1]), -1)
	}

	// Undo pre-whitening
	ia ^= tf.k[0]
	ib ^= tf.k[1]
	ic ^= tf.k[2]
	id ^= tf.k[3]

	store32l(mut dst[0..4], ia)
	store32l(mut dst[4..8], ib)
	store32l(mut dst[8..12], ic)
	store32l(mut dst[12..16], id)
}

// store32l stores src in dst in little-endian form.
fn store32l(mut dst []u8, src u32) {
	dst[0] = u8(src)
	dst[1] = u8(src >> 8)
	dst[2] = u8(src >> 16)
	dst[3] = u8(src >> 24)
	return
}

// load32l reads a little-endian u32 from src.
fn load32l(src []u8) u32 {
	return u32(src[0]) | u32(src[1]) << 8 | u32(src[2]) << 16 | u32(src[3]) << 24
}

// gf_mult returns a*b in GF(2^8)/p
fn gf_mult(a_ u8, b_ u8, p_ u32) u8 {
	mut a := a_
	mut b := [u32(0), u32(b_)]
	mut p := [u32(0), u32(p_)]
	mut result := u32(0)

	// branchless GF multiplier
	for i := 0; i < 7; i++ {
		result ^= b[a & 1]
		a >>= 1
		b[1] = p[b[1] >> 7] ^ (b[1] << 1)
	}
	result ^= b[a & 1]
	return u8(result)
}

// mds_column_mult calculates y{col} where [y0 y1 y2 y3] = mds * [x0]
fn mds_column_mult(inp u8, col int) u32 {
	mul01 := inp
	mul5b := gf_mult(inp, 0x5B, twofish.mds_polynomial)
	mul_ef := gf_mult(inp, 0xEF, twofish.mds_polynomial)

	match col {
		0 {
			return u32(mul01) | u32(mul5b) << 8 | u32(mul_ef) << 16 | u32(mul_ef) << 24
		}
		1 {
			return u32(mul_ef) | u32(mul_ef) << 8 | u32(mul5b) << 16 | u32(mul01) << 24
		}
		2 {
			return u32(mul5b) | u32(mul_ef) << 8 | u32(mul01) << 16 | u32(mul_ef) << 24
		}
		3 {
			return u32(mul5b) | u32(mul01) << 8 | u32(mul_ef) << 16 | u32(mul5b) << 24
		}
		else {
			panic('v_crypto/twofish: unreachable')
		}
	}
	panic('v_crypto/twofish: unreachable')
}

// h implements the s-box generation function.
fn h(inp []u8, key []u8, offset int) u32 {
	mut y := []u8{len: 4}
	for x, _ in y {
		y[x] = inp[x]
	}

	match key.len / 8 {
		4 {
			y[0] = twofish.sbox[1][y[0]] ^ key[4 * (6 + offset) + 0]
			y[1] = twofish.sbox[0][y[1]] ^ key[4 * (6 + offset) + 1]
			y[2] = twofish.sbox[0][y[2]] ^ key[4 * (6 + offset) + 2]
			y[3] = twofish.sbox[1][y[3]] ^ key[4 * (6 + offset) + 3]

			y[0] = twofish.sbox[1][y[0]] ^ key[4 * (4 + offset) + 0]
			y[1] = twofish.sbox[1][y[1]] ^ key[4 * (4 + offset) + 1]
			y[2] = twofish.sbox[0][y[2]] ^ key[4 * (4 + offset) + 2]
			y[3] = twofish.sbox[0][y[3]] ^ key[4 * (4 + offset) + 3]

			y[0] = twofish.sbox[1][twofish.sbox[0][twofish.sbox[0][y[0]] ^ key[4 * (2 + offset) + 0]] ^ key[
				4 * (0 + offset) + 0]]
			y[1] = twofish.sbox[0][twofish.sbox[0][twofish.sbox[1][y[1]] ^ key[4 * (2 + offset) + 1]] ^ key[
				4 * (0 + offset) + 1]]
			y[2] = twofish.sbox[1][twofish.sbox[1][twofish.sbox[0][y[2]] ^ key[4 * (2 + offset) + 2]] ^ key[
				4 * (0 + offset) + 2]]
			y[3] = twofish.sbox[0][twofish.sbox[1][twofish.sbox[1][y[3]] ^ key[4 * (2 + offset) + 3]] ^ key[
				4 * (0 + offset) + 3]]
		}
		3 {
			y[0] = twofish.sbox[1][y[0]] ^ key[4 * (4 + offset) + 0]
			y[1] = twofish.sbox[1][y[1]] ^ key[4 * (4 + offset) + 1]
			y[2] = twofish.sbox[0][y[2]] ^ key[4 * (4 + offset) + 2]
			y[3] = twofish.sbox[0][y[3]] ^ key[4 * (4 + offset) + 3]

			y[0] = twofish.sbox[1][twofish.sbox[0][twofish.sbox[0][y[0]] ^ key[4 * (2 + offset) + 0]] ^ key[
				4 * (0 + offset) + 0]]
			y[1] = twofish.sbox[0][twofish.sbox[0][twofish.sbox[1][y[1]] ^ key[4 * (2 + offset) + 1]] ^ key[
				4 * (0 + offset) + 1]]
			y[2] = twofish.sbox[1][twofish.sbox[1][twofish.sbox[0][y[2]] ^ key[4 * (2 + offset) + 2]] ^ key[
				4 * (0 + offset) + 2]]
			y[3] = twofish.sbox[0][twofish.sbox[1][twofish.sbox[1][y[3]] ^ key[4 * (2 + offset) + 3]] ^ key[
				4 * (0 + offset) + 3]]
		}
		2 {
			y[0] = twofish.sbox[1][twofish.sbox[0][twofish.sbox[0][y[0]] ^ key[4 * (2 + offset) + 0]] ^ key[
				4 * (0 + offset) + 0]]
			y[1] = twofish.sbox[0][twofish.sbox[0][twofish.sbox[1][y[1]] ^ key[4 * (2 + offset) + 1]] ^ key[
				4 * (0 + offset) + 1]]
			y[2] = twofish.sbox[1][twofish.sbox[1][twofish.sbox[0][y[2]] ^ key[4 * (2 + offset) + 2]] ^ key[
				4 * (0 + offset) + 2]]
			y[3] = twofish.sbox[0][twofish.sbox[1][twofish.sbox[1][y[3]] ^ key[4 * (2 + offset) + 3]] ^ key[
				4 * (0 + offset) + 3]]
		}
		else {
			panic('v_crypto/twofish: unreachable')
		}
	}

	// [y0 y1 y2 y3] = mds * [x0 x1 x2 x3]
	mut mds_mult := u32(0)
	for i, _ in y {
		mds_mult ^= mds_column_mult(y[i], i)
	}
	return mds_mult
}
