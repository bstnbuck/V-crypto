module salsa20

// Salsa20 symmetric key stream cipher encryption
import math.bits
import crypto.cipher
import crypto.internal.subtle
import encoding.binary

// size of Salsa20 key, 256 bits
pub const key_size = 32

// size of ietf Salsa20 nonce, 64 bits
pub const nonce_size = 8

// size of extended Salsa20 nonce, XSalsa20, 192 bits
pub const x_nonce_size = 24

// internal block size Salsa20 operates on, in bytes
const block_size = 64

// vfmt off
// four constants of Salsa20 state.
const cc0 = u32(0x61707865) // expa
const cc1 = u32(0x3320646e) // nd 3
const cc2 = u32(0x79622d32) // 2-by
const cc3 = u32(0x6b206574) // te k

// vfmt on
// Cipher represents Salsa20 stream cipher instances.
struct Cipher {
mut:
	// internal Salsa20 states, 4 Salsa20 constants,
	// 8 word (32 bytes) key, 2 word nonce and 2 word counter
	key     []u32
	nonce   []u32
	counter u64
	rounds  int = 20
	// internal buffer for storing key stream results
	block []u8 = []u8{len: salsa20.block_size}
}

// free the resources taken by the Cipher `c`. Dont use cipher after .free call
@[unsafe]
pub fn (mut c Cipher) free() {
	$if prealloc {
		return
	}
	unsafe {
		c.block.free()
	}
}

// new_cipher creates a new Salsa20 stream cipher with the given 32 bytes key, a 8 or 24 bytes nonce and returns a new Cipher object or an error.
// If 24 bytes of nonce are provided, the XSalsa20 construction will be used.
pub fn new_cipher(key []u8, nonce []u8) !&Cipher {
	mut c := &Cipher{}

	c.reset()
	c.init(key, nonce, 0)!

	return c
}

// encrypt encrypts plaintext bytes with a Salsa20 cipher instance with provided key and nonce.
// It is a thin wrapper around two supported nonce sizes, Salsa20 with 64 bits
// and XSalsa20 with 192 bits nonce. Internally, encrypt start with 0's counter value.
// If you want more control, use Cipher instance and setup the counter by your self.
pub fn encrypt(key []u8, nonce []u8, plaintext []u8) ![]u8 {
	return salsa20_crypt(key, nonce, plaintext)
}

// decrypt does reverse of encrypt operation by decrypting ciphertext with salsa20 cipher
// instance with provided key and nonce.
pub fn decrypt(key []u8, nonce []u8, ciphertext []u8) ![]u8 {
	return salsa20_crypt(key, nonce, ciphertext)
}

// set_counter sets the Salsa20 counter
pub fn (mut c Cipher) set_counter(ctr u64) {
	if ctr >= max_u64 {
		panic('v_crypto/salsa20: counter would overflow')
	}
	c.counter = ctr
}

// rekey reinitializes a given Salsa20 instance with the provided key, nonce, different counter (>=0) and number of rounds (allowed are 8, 12, 20).
pub fn (mut c Cipher) rekey(key []u8, nonce []u8, counter u64, rounds int) ! {
	c.reset()

	// set different amount of rounds
	match rounds {
		8, 12, 20 {
			c.rounds = rounds
		}
		else {
			return error('v_crypto/salsa20: invalid amount of rounds (8, 12, 20): $rounds')
		}
	}

	c.init(key, nonce, counter)!
}

// helper and core functions
//
//
// reset resets all parameters to their initial state
fn (mut c Cipher) reset() {
	c.key = []u32{len: 8, init: 0}
	c.nonce = []u32{len: 2, init: 0}
	c.counter = u64(0)
	c.rounds = 20
}

// init reinitializes Salsa20 instance with the provided key and nonce.
fn (mut c Cipher) init(key_ []u8, nonce_ []u8, counter u64) ! {
	// check for correctness of key and nonce length
	if key_.len != salsa20.key_size {
		return error('v_crypto/salsa20: bad key size provided: ${key_.len}')
	}

	// check for nonce's length is 8 or 24
	if nonce_.len != salsa20.nonce_size && nonce_.len != salsa20.x_nonce_size {
		return error('v_crypto/salsa20: bad nonce size provided: ${nonce_.len}')
	}

	mut nonce := nonce_.clone()
	mut key := key_.clone()

	// if nonce's length is 24 bytes, we derive a new key and nonce with xsalsa20 function
	// and supplied to setup process.
	if nonce.len == salsa20.x_nonce_size {
		key = xsalsa20(key_, nonce[0..16], c.rounds)!
		mut cnonce := []u8{len: salsa20.nonce_size}
		_ := copy(mut cnonce[0..8], nonce[16..24])
		nonce = cnonce.clone()
	}

	// setup salsa20 cipher key
	c.key[0] = binary.little_endian_u32(key[0..4])
	c.key[1] = binary.little_endian_u32(key[4..8])
	c.key[2] = binary.little_endian_u32(key[8..12])
	c.key[3] = binary.little_endian_u32(key[12..16])
	c.key[4] = binary.little_endian_u32(key[16..20])
	c.key[5] = binary.little_endian_u32(key[20..24])
	c.key[6] = binary.little_endian_u32(key[24..28])
	c.key[7] = binary.little_endian_u32(key[28..32])

	// setup salsa20 cipher nonce
	c.nonce[0] = binary.little_endian_u32(nonce[0..4])
	c.nonce[1] = binary.little_endian_u32(nonce[4..8])

	c.counter = counter
}

// xor_key_stream xors each byte in the given slice in the src with a byte from the
// cipher's key stream. It fulfills `cipher.Stream` interface. It encrypts the plaintext message
// in src and stores the ciphertext result in dst in a single run of encryption.
// For security reasons (key, nonce) pair must never be the same more than once for encryption.
// This would void any confidentiality guarantees for the messages encrypted with the same nonce and key.
@[direct_array_access]
pub fn (mut c Cipher) xor_key_stream(mut dst []u8, src []u8) {
	if src.len == 0 {
		return
	}
	if dst.len < src.len {
		panic('v_crypto/salsa20: dst buffer is too small')
	}
	if subtle.inexact_overlap(dst, src) {
		panic('v_crypto/salsa20: invalid buffer overlap')
	}

	// number of blocks the src bytes should be split into
	nr_blocks := src.len / salsa20.block_size
	for i := 0; i < nr_blocks; i++ {
		// generate ciphers keystream block, stored in c.block
		c.salsa20_block()

		// get current src block to be xor-ed
		block := unsafe { src[i * salsa20.block_size..(i + 1) * salsa20.block_size] }

		// instead allocating output buffer for every block, we use dst buffer directly.
		// xor current block of plaintext with keystream in c.block
		n := cipher.xor_bytes(mut dst[i * salsa20.block_size..(i + 1) * salsa20.block_size],
			block, c.block)
		if n != c.block.len {
			panic("v_crypto/salsa20: block len and xor'ed bits are not the same")
		}
	}

	// process for partial block
	if src.len % salsa20.block_size != 0 {
		c.salsa20_block()

		// get the remaining last partial block
		block := unsafe { src[nr_blocks * salsa20.block_size..] }

		// xor block with keystream
		_ := cipher.xor_bytes(mut dst[nr_blocks * salsa20.block_size..], block, c.block)
	}
}

// salsa20_crypt performs the encryption/decryption process, it only works with encrypt() and decrypt()
fn salsa20_crypt(key []u8, nonce []u8, plaintext []u8) ![]u8 {
	mut c := new_cipher(key, nonce)!

	mut out := []u8{len: plaintext.len}
	c.xor_key_stream(mut out, plaintext)

	return out
}

// salsa20_block transforms a Salsa20 state by running multiple quarter rounds.
@[direct_array_access]
fn (mut c Cipher) salsa20_block() {
	// initializes Salsa20 state
	//      0:cccccccc   1:kkkkkkkk   2:cccccccc   3:cccccccc
	//      4:kkkkkkkk   5:cccccccc   6:nnnnnnnn   7:nnnnnnnn
	//      8:bbbbbbbb   9:bbbbbbbb  10:cccccccc  11:kkkkkkkk
	//     12:kkkkkkkk  13:kkkkkkkk  14:kkkkkkkk  15:cccccccc
	//
	// where c=constant k=key b=blockcounter n=nonce
	mut c_tmp := []u8{len: 8, init: 0}
	binary.little_endian_put_u64(mut c_tmp, c.counter)
	cp1 := binary.little_endian_u32(c_tmp[0..3])
	cp2 := binary.little_endian_u32(c_tmp[4..7])

	mut x := []u32{len: 16, init: 0}
	x[0], x[1], x[2], x[3] = salsa20.cc0, c.key[0], c.key[1], c.key[2]
	x[4], x[5], x[6], x[7] = c.key[3], salsa20.cc1, c.nonce[0], c.nonce[1]
	x[8], x[9], x[10], x[11] = cp1, cp2, salsa20.cc2, c.key[4]
	x[12], x[13], x[14], x[15] = c.key[5], c.key[6], c.key[7], salsa20.cc3

	for i := 0; i < c.rounds / 2; i++ {
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

	// add back to initial state and stores to dst
	x[0] += salsa20.cc0
	x[1] += c.key[0]
	x[2] += c.key[1]
	x[3] += c.key[2]
	x[4] += c.key[3]
	x[5] += salsa20.cc1
	x[6] += c.nonce[0]
	x[7] += c.nonce[1]
	x[8] += cp1
	x[9] += cp2
	x[10] += salsa20.cc2
	x[11] += c.key[4]
	x[12] += c.key[5]
	x[13] += c.key[6]
	x[14] += c.key[7]
	x[15] += salsa20.cc3

	binary.little_endian_put_u32(mut c.block[0..4], x[0])
	binary.little_endian_put_u32(mut c.block[4..8], x[1])
	binary.little_endian_put_u32(mut c.block[8..12], x[2])
	binary.little_endian_put_u32(mut c.block[12..16], x[3])
	binary.little_endian_put_u32(mut c.block[16..20], x[4])
	binary.little_endian_put_u32(mut c.block[20..24], x[5])
	binary.little_endian_put_u32(mut c.block[24..28], x[6])
	binary.little_endian_put_u32(mut c.block[28..32], x[7])
	binary.little_endian_put_u32(mut c.block[32..36], x[8])
	binary.little_endian_put_u32(mut c.block[36..40], x[9])
	binary.little_endian_put_u32(mut c.block[40..44], x[10])
	binary.little_endian_put_u32(mut c.block[44..48], x[11])
	binary.little_endian_put_u32(mut c.block[48..52], x[12])
	binary.little_endian_put_u32(mut c.block[52..56], x[13])
	binary.little_endian_put_u32(mut c.block[56..60], x[14])
	binary.little_endian_put_u32(mut c.block[60..64], x[15])

	// updates counter and checks for overflow
	ctr := c.counter + u64(1)
	if ctr >= max_u64 {
		panic('v_crypto/salsa20: counter overflow')
	}
	c.counter += u64(1)
}

// quarter_round is the basic operation of the Salsa algorithm. It operates
// on four 32-bit unsigned integers, by performing ARX (add, rotate, xor)
// operation on this quartet u32 numbers.
fn quarter_round(a u32, b u32, c u32, d u32) (u32, u32, u32, u32) {
	// The operation is as follows (in C-like notation):
	// where `<<<` denotes 32 bits rotate left operation
	// b ^= (a + d) <<< 7;
	// c ^= (b + a) <<< 9;
	// d ^= (c + b) <<< 13;
	// a ^= (d + c) <<< 18;
	mut ax := a
	mut bx := b
	mut cx := c
	mut dx := d

	bx ^= bits.rotate_left_32((ax + dx), 7)
	cx ^= bits.rotate_left_32((bx + ax), 9)
	dx ^= bits.rotate_left_32((cx + bx), 13)
	ax ^= bits.rotate_left_32((dx + cx), 18)

	return ax, bx, cx, dx
}
