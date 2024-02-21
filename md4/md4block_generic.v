module md4

import encoding.binary

// block calculates each of the MD4 rounds with given data and num_blocks
fn (mut dig Digest) block(mut data []u8, num_blocks int) {
	mut a := dig.s[0]
	mut b := dig.s[1]
	mut c := dig.s[2]
	mut d := dig.s[3]

	mut x := []u32{len: 16}

	for i := 0; i < num_blocks; i++ {
		for j := 0; j < 16; j++ {
			x[j] = binary.little_endian_u32(data[(i * 64) + (j * 4)..])
		}

		aa := a
		bb := b
		cc := c
		dd := d

		// round 1
		for j := 0; j < 4; j++ {
			a += ((b & c) | ((~b) & d)) + x[(j * 4) + 0]
			a = (a << 3) | (a >> (32 - 3))
			d += ((a & b) | ((~a) & c)) + x[(j * 4) + 1]
			d = (d << 7) | (d >> (32 - 7))
			c += ((d & a) | ((~d) & b)) + x[(j * 4) + 2]
			c = (c << 11) | (c >> (32 - 11))
			b += ((c & d) | ((~c) & a)) + x[(j * 4) + 3]
			b = (b << 19) | (b >> (32 - 19))
		}

		// round 2
		for j := 0; j < 4; j++ {
			a += ((b & c) | (b & d) | (c & d)) + x[0 + j] + 0x5a827999
			a = (a << 3) | (a >> (32 - 3))
			d += ((a & b) | (a & c) | (b & c)) + x[4 + j] + 0x5a827999
			d = (d << 5) | (d >> (32 - 5))
			c += ((d & a) | (d & b) | (a & b)) + x[8 + j] + 0x5a827999
			c = (c << 9) | (c >> (32 - 9))
			b += ((c & d) | (c & a) | (d & a)) + x[12 + j] + 0x5a827999
			b = (b << 13) | (b >> (32 - 13))
		}

		r3x := fn (l u32) u32 {
			return ((l & 0x1) << 3) | ((l & 0x2) << 1) | ((l & 0x4) >> 1) | ((l & 0x8) >> 3)
		}

		// round 3
		for j := 0; j < 4; j++ {
			a += (b ^ c ^ d) + x[r3x(u32(j * 4))] + 0x6Ed9Eba1
			a = (a << 3) | (a >> (32 - 3))
			d += (a ^ b ^ c) + x[r3x(u32(j * 4) + 1)] + 0x6Ed9Eba1
			d = (d << 9) | (d >> (32 - 9))
			c += (d ^ a ^ b) + x[r3x(u32(j * 4) + 2)] + 0x6Ed9Eba1
			c = (c << 11) | (c >> (32 - 11))
			b += (c ^ d ^ a) + x[r3x(u32(j * 4) + 3)] + 0x6Ed9Eba1
			b = (b << 15) | (b >> (32 - 15))
		}

		a = aa + a
		b = bb + b
		c = cc + c
		d = dd + d
	}

	dig.s[0] = a
	dig.s[1] = b
	dig.s[2] = c
	dig.s[3] = d
}
