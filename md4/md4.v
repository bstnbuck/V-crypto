// Module md4 implements the MD4 checksum algorithm as defined in RFc 1320.
//
// deprecated: MD4 is cryptographically broken and should should only be used
// where compatibility with legacy systems, not security, is the goal. Instead,
// use a secure checksum like SHa-256 (from crypto/sha256).
//
// Based off: https://github.com/golang/crypto/blob/master/md4/md4.go
// and: https://github.com/golang/crypto/blob/master/md4/md4block.go

module md4

import encoding.binary

// The size of an MD4 checksum in bytes.
pub const size = 16

// The blocksize of MD4 in bytes.
pub const block_size = 64

// const chunk = 64
const init0 = u32(0x67452301)
const init1 = u32(0xEFcdab89)
const init2 = u32(0x98badcFE)
const init3 = u32(0x10325476)

struct Digest {
mut:
	s []u32
	// x   []u8
	// nx  int
	// len u64
}

fn (mut d Digest) init() {
	d.s = []u32{len: 4}
	// d.x = []u8{len: md4.chunk}
	d.reset()
}

// reset the state of the Digest `d`
pub fn (mut d Digest) reset() {
	d.s[0] = u32(md4.init0)
	d.s[1] = u32(md4.init1)
	d.s[2] = u32(md4.init2)
	d.s[3] = u32(md4.init3)
	// d.nx = 0
	// d.len = 0
}

// new returns a new Digest (implementing checksum.checksum) computing the MD4 checksum.
pub fn new() &Digest {
	$if prod {
		println('MD4 is a legacy and insecure checksum algorithm and should not be used in production environments.')
	}
	mut d := &Digest{}
	d.init()
	return d
}

// size returns the size of the checksum in bytes.
pub fn (d &Digest) size() int {
	return md4.size
}

// block_size returns the block size of the checksum in bytes.
pub fn (d &Digest) block_size() int {
	return md4.block_size
}

// checksum computes the MD4 hash of given msg and returns the padded block length and the corresponding MD4 hash
pub fn (mut d Digest) checksum(msg []u8) (int, []u8) {
	// MD4 padding
	byte_len := msg.len
	bit_len := byte_len * 8

	mut zeros := (448 - (bit_len + 1)) % 512
	if zeros < 0 {
		zeros += 512
	}

	bits_pad := md4.block_size + 1 + zeros
	byte_pad := bits_pad / 8

	mut pad_msg := []u8{len: byte_len + byte_pad}

	copy(mut pad_msg, msg)

	pad_msg[byte_len] = 0x80
	binary.little_endian_put_u64(mut pad_msg[pad_msg.len - 8..], u64(bit_len))

	num_blocks := pad_msg.len / md4.block_size

	// execute rounds
	d.block(mut pad_msg, num_blocks)

	mut checksum := []u8{len: md4.size}
	binary.little_endian_put_u32(mut checksum[0..], d.s[0])
	binary.little_endian_put_u32(mut checksum[4..], d.s[1])
	binary.little_endian_put_u32(mut checksum[8..], d.s[2])
	binary.little_endian_put_u32(mut checksum[12..], d.s[3])

	return pad_msg.len, checksum
}

// hexhash returns a hexadecimal MD4 checksum as a `string` of given input `s`.
pub fn hexhash(s string) string {
	mut d := new()
	d.init()
	// d.write(s.bytes())
	// return d.sum([]).hex()
	_, hash := d.checksum(s.bytes())
	return hash.hex()
}

pub fn (mut d Digest) write(p_ []u8) int {
	println('not implemented yet')
	return 0
	/*
	unsafe {
		mut p := p_.clone()
		nn := p.len
		d.len += u64(nn)
		if d.nx > 0 {
			mut n := p.len
			if n > md4.chunk - d.nx {
				n = md4.chunk - d.nx
			}
			for i := 0; i < n; i++ {
				d.x[d.nx + i] = p[i]
			}
			d.nx += n
			if d.nx == md4.chunk {
				d.block(d.x[0..])
				d.nx = 0
			}
			p = p[n..]
		}
		n := d.block(p)
		p = p[n..].clone()
		if p.len > 0 {
			d.nx = copy(mut d.x, p)
		}
		return nn
		
	}
	*/
}

fn (d0 &Digest) sum(data []u8) []u8 {
	println('not implemented yet')
	return [u8(0x00)]
	/*
	// Make a copy of d0, so that caller can keep writing and summing.
	mut d := new()
	d = d0.clone()

	// Padding.  add a 1 bit and 0 bits until 56 bytes mod 64.
	mut l := d.len

	mut tmp := []u8{len: 64}
	tmp[0] = 0x80
	if (l % 64) < 56 {
		d.write(tmp[0..((56 - l) % 64)])
	} else {
		d.write(tmp[0..((64 + 56 - l) % 64)])
	}

	// Length in bits.
	l <<= 3
	for i := u32(0); i < 8; i++ {
		tmp[i] = u8(l >> (8 * i))
	}
	d.write(tmp[0..8])
	
	if d.nx != 0 {
		panic('d.nx != 0')
	}

	mut digest := []u8{len: md4.size}
	binary.little_endian_put_u32(mut digest, d.s[0])
	binary.little_endian_put_u32(mut digest[4..], d.s[1])
	binary.little_endian_put_u32(mut digest[8..], d.s[2])
	binary.little_endian_put_u32(mut digest[12..], d.s[3])
	return digest
	*/
}
