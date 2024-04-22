module twofish

fn test_twofish() {
	key1 := [u8(0x9F), 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32, 0xB6, 0xBF, 0xEC, 0x2F, 0x2A,
		0xE8, 0xC3, 0x5A]
	plain1 := [u8(0xD4), 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E, 0x86, 0xCB, 0x08, 0x6B, 0x78,
		0x9F, 0x54, 0x19]
	enc1 := [u8(0x01), 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85, 0x8F, 0xAA, 0xC3, 0xA3, 0xBA,
		0x20, 0xFB, 0xC3]

	key2 := [u8(0x88), 0xB2, 0xB2, 0x70, 0x6B, 0x10, 0x5E, 0x36, 0xB4, 0x46, 0xBB, 0x6D, 0x73,
		0x1A, 0x1E, 0x88, 0xEF, 0xA7, 0x1F, 0x78, 0x89, 0x65, 0xBD, 0x44]
	plain2 := [u8(0x39), 0xDA, 0x69, 0xD6, 0xBA, 0x49, 0x97, 0xD5, 0x85, 0xB6, 0xDC, 0x07, 0x3C,
		0xA3, 0x41, 0xB2]
	enc2 := [u8(0x18), 0x2B, 0x02, 0xD8, 0x14, 0x97, 0xEA, 0x45, 0xF9, 0xDA, 0xAC, 0xDC, 0x29,
		0x19, 0x3A, 0x65]

	key3 := [u8(0xD4), 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46, 0xF2, 0xA2, 0x82, 0xB7, 0xD4,
		0x5B, 0x4E, 0x0D, 0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B, 0xD7, 0xFC, 0x01, 0x70,
		0x0C, 0xC8, 0x21, 0x6F]
	plain3 := [u8(0x90), 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F, 0x2C, 0x32, 0xDC, 0x23, 0x9B,
		0x26, 0x35, 0xE6]
	enc3 := [u8(0x6C), 0xB4, 0x56, 0x1C, 0x40, 0xBF, 0x0A, 0x97, 0x05, 0x93, 0x1C, 0xB6, 0xD4,
		0x08, 0xE7, 0xFA]

	mut tf1 := new_cipher(key1)!
	mut dst1 := []u8{len: 16}
	tf1.encrypt(mut dst1, plain1)
	assert dst1 == enc1
	tf1.decrypt(mut dst1, enc1)
	assert dst1 == plain1

	mut tf2 := new_cipher(key2)!
	mut dst2 := []u8{len: 16}
	tf2.encrypt(mut dst2, plain2)
	assert dst2 == enc2
	tf2.decrypt(mut dst2, enc2)
	assert dst2 == plain2

	mut tf3 := new_cipher(key3)!
	mut dst3 := []u8{len: 16}
	tf3.encrypt(mut dst3, plain3)
	assert dst3 == enc3
	tf3.decrypt(mut dst3, enc3)
	assert dst3 == plain3
}
