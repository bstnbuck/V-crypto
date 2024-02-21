module xtea

fn test_simple_xtea() {
	key0 := [u8(0x00), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00]
	plain0 := [u8(0x00), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
	enc0 := [u8(0xDE), 0xE9, 0xD4, 0xD8, 0xF7, 0x13, 0x1E, 0xD9]

	key1 := [u8(0x00), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00]
	plain1 := [u8(0x01), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
	enc1 := [u8(0x06), 0x5C, 0x1B, 0x89, 0x75, 0xC6, 0xA8, 0x16]

	key2 := [u8(0x01), 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34,
		0x56, 0x78, 0x9A]
	plain2 := [u8(0x00), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
	enc2 := [u8(0x1F), 0xF9, 0xA0, 0x26, 0x1A, 0xC6, 0x42, 0x64]

	key3 := [u8(0x01), 0x23, 0x45, 0x67, 0x12, 0x34, 0x56, 0x78, 0x23, 0x45, 0x67, 0x89, 0x34,
		0x56, 0x78, 0x9A]
	plain3 := [u8(0x01), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
	enc3 := [u8(0x8C), 0x67, 0x15, 0x5B, 0x2E, 0xF9, 0x1E, 0xAD]

	// part 1
	x0 := new(key0) or { panic(err) }
	mut dst0 := []u8{len: plain0.len}
	x0.encrypt(mut dst0, plain0)
	assert dst0 == enc0
	mut src0 := []u8{len: plain0.len}
	x0.decrypt(mut src0, enc0)
	assert src0 == plain0

	// part 2
	x1 := new(key1) or { panic(err) }
	mut dst1 := []u8{len: plain1.len}
	x1.encrypt(mut dst1, plain1)
	assert dst1 == enc1
	mut src1 := []u8{len: plain1.len}
	x1.decrypt(mut src1, enc1)
	assert src1 == plain1

	// part 1
	x2 := new(key2) or { panic(err) }
	mut dst2 := []u8{len: plain2.len}
	x2.encrypt(mut dst2, plain2)
	assert dst2 == enc2
	mut src2 := []u8{len: plain2.len}
	x2.decrypt(mut src2, enc2)
	assert src2 == plain2

	// part 1
	x3 := new(key3) or { panic(err) }
	mut dst3 := []u8{len: plain3.len}
	x3.encrypt(mut dst3, plain3)
	assert dst3 == enc3
	mut src3 := []u8{len: plain3.len}
	x3.decrypt(mut src3, enc3)
	assert src3 == plain3
}

fn test_invalid_key() {
	key := [u8(0x00), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00] // , 0x00
	x := new(key) or {
		assert true
		return
	}
	assert false
}
