module cipher_

import crypto.aes

fn test_aes_ige() {
	key1 := [u8(0x00), 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
		0x0D, 0x0E, 0x0F]
	key2 := [u8(0x54), 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x6E, 0x20, 0x69, 0x6D,
		0x70, 0x6C, 0x65]

	iv1 := [u8(0x00), 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
		0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
		0x1D, 0x1E, 0x1F]
	iv2 := [u8(0x6D), 0x65, 0x6E, 0x74, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x6F, 0x66, 0x20, 0x49,
		0x47, 0x45, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x4F, 0x70, 0x65,
		0x6E, 0x53, 0x53]

	plain1 := [u8(0x00), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00]
	plain2 := [u8(0x99), 0x70, 0x64, 0x87, 0xA1, 0xCD, 0xE6, 0x13, 0xBC, 0x6D, 0xE0, 0xB6, 0xF2,
		0x4B, 0x1C, 0x7A, 0xA4, 0x48, 0xC8, 0xB9, 0xC3, 0x40, 0x3E, 0x34, 0x67, 0xA8, 0xCA, 0xD8,
		0x93, 0x40, 0xF5, 0x3B]

	out1 := [u8(0x1A), 0x85, 0x19, 0xA6, 0x55, 0x7B, 0xE6, 0x52, 0xE9, 0xDA, 0x8E, 0x43, 0xDA,
		0x4E, 0xF4, 0x45, 0x3C, 0xF4, 0x56, 0xB4, 0xCA, 0x48, 0x8A, 0xA3, 0x83, 0xC7, 0x9C, 0x98,
		0xB3, 0x47, 0x97, 0xCB]
	out2 := [u8(0x4C), 0x2E, 0x20, 0x4C, 0x65, 0x74, 0x27, 0x73, 0x20, 0x68, 0x6F, 0x70, 0x65,
		0x20, 0x42, 0x65, 0x6E, 0x20, 0x67, 0x6F, 0x74, 0x20, 0x69, 0x74, 0x20, 0x72, 0x69, 0x67,
		0x68, 0x74, 0x21, 0x0A]

	block1 := aes.new_cipher(key1)
	mut mode1 := new_ige(block1, iv1)!
	mut dst1 := []u8{len: plain1.len}
	mode1.encrypt_blocks(mut dst1, plain1)
	assert dst1 == out1
	mode1.decrypt_blocks(mut dst1, dst1.clone())
	assert dst1 == plain1

	block2 := aes.new_cipher(key2)
	mut mode2 := new_ige(block2, iv2)!
	mut dst2 := []u8{len: out2.len}
	mode2.encrypt_blocks(mut dst2, plain2)
	assert dst2 == out2
	mode2.decrypt_blocks(mut dst2, dst2.clone())
	assert dst2 == plain2
}
