module salsa20

// eXtended Salsa20 stream cipher (XSalsa20)
import encoding.binary

// HSalsa20 nonce size
const h_nonce_size = 16

// xsalsa20 is a intermediate step to build XSalsa20 and initialize the same way as the ChaCha20 cipher,
// except xsalsa20 use a 192-bit (24 byte) nonce and has no counter to derive the subkey.
@[direct_array_access]
fn xsalsa20(key []u8, nonce []u8, rounds int) ![]u8 {
	// early bound check
	if key.len != key_size {
		return error('v_crypto/xsalsa20: Bad key size ${key.len}')
	}
	if nonce.len != salsa20.h_nonce_size {
		return error('v_crypto/xsalsa20: Bad nonce size ${nonce.len}')
	}

	mut x := []u32{len: 16, init: 0}
	x[0], x[1], x[2], x[3] = cc0, binary.little_endian_u32(key[0..4]), binary.little_endian_u32(key[4..8]), binary.little_endian_u32(key[8..12])
	x[4], x[5], x[6], x[7] = binary.little_endian_u32(key[12..16]), cc1, binary.little_endian_u32(nonce[0..4]), binary.little_endian_u32(nonce[4..8])
	x[8], x[9], x[10], x[11] = binary.little_endian_u32(nonce[8..12]), binary.little_endian_u32(nonce[12..16]), cc2, binary.little_endian_u32(key[16..20])
	x[12], x[13], x[14], x[15] = binary.little_endian_u32(key[20..24]), binary.little_endian_u32(key[24..28]), binary.little_endian_u32(key[28..32]), cc3

	for i := 0; i < rounds / 2; i++ {
		// column round
		x[0], x[4], x[8], x[12] = quarter_round(x[0], x[4], x[8], x[12]) // column 1
		x[5], x[9], x[13], x[1] = quarter_round(x[5], x[9], x[13], x[1]) // column 2
		x[10], x[14], x[2], x[6] = quarter_round(x[10], x[14], x[2], x[6]) // column 3
		x[15], x[3], x[7], x[11] = quarter_round(x[15], x[3], x[7], x[11]) // column 4
		// row round
		x[0], x[1], x[2], x[3] = quarter_round(x[0], x[1], x[2], x[3]) // row 1
		x[5], x[6], x[7], x[4] = quarter_round(x[5], x[6], x[7], x[4]) // row 2
		x[10], x[11], x[8], x[9] = quarter_round(x[10], x[11], x[8], x[9]) // row 3
		x[15], x[12], x[13], x[14] = quarter_round(x[15], x[12], x[13], x[14]) // row 4
	}

	mut out := []u8{len: 32}
	binary.little_endian_put_u32(mut out[0..4], x[0])
	binary.little_endian_put_u32(mut out[4..8], x[5])
	binary.little_endian_put_u32(mut out[8..12], x[10])
	binary.little_endian_put_u32(mut out[12..16], x[15])
	binary.little_endian_put_u32(mut out[16..20], x[6])
	binary.little_endian_put_u32(mut out[20..24], x[7])
	binary.little_endian_put_u32(mut out[24..28], x[8])
	binary.little_endian_put_u32(mut out[28..32], x[9])

	return out
}
