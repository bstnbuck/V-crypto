module ripemd160

fn test_blocksize() {
	mut d := new()
	d.init()
	assert d.block_size() == 64
}

fn test_size() {
	mut d := new()
	d.init()
	assert d.size() == 20
}

fn test_ripemd160_hexhash() {
	assert hexhash('') == '9c1185a5c5e9fc54612808977ee8f548b2258d31'
	assert hexhash('message digest') == '5d0689ef49d2fae572b881b123a85ffa21595f36'
}

fn test_ripemd160_full() {
	mut d := new()
	d.init()
	d.write(''.bytes()) or { assert false }
	assert d.sum([]).hex() == '9c1185a5c5e9fc54612808977ee8f548b2258d31'

	d.reset()

	d.write('a'.bytes()) or { assert false }
	assert d.sum([]).hex() == '0bdc9d2d256b3ee9daae347be6f4dc835a467ffe'

	d.reset()

	d.write('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.bytes()) or {
		assert false
	}
	assert d.sum([]).hex() == 'b0e20b6e3116640286ed3a87a5713079b21f5189'

	d.reset()

	d.write('12345678901234567890123456789012345678901234567890123456789012345678901234567890'.bytes()) or {
		assert false
	}
	assert d.sum([]).hex() == '9b752e45573d4b39f4dbd3323cab82bf63326bfb'

	d.reset()

	d.write('Hello from v_crypto RIPEMD-160 implemented in pure V!'.bytes()) or { assert false }
	assert d.sum([]).hex() == '0d33ed8a6a5dc2bdcab081cecadd2fad0cb35ed8'
}
