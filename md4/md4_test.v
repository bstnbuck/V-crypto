module md4

fn test_standards() {
	mut d := new()
	d.init()
	assert d.block_size() == block_size
	assert d.size() == size
}

fn test_simple_md4() {
	mut d := new()
	d.init()
	d.write('test'.bytes())
	assert d.sum([]) == [u8(0x00)]
	_, hash := d.checksum('test'.bytes())
	assert hash == [u8(219), 52, 109, 105, 29, 122, 204, 77, 194, 98, 93, 177, 159, 158, 63, 82]
	assert hash.hex() == 'db346d691d7acc4dc2625db19f9e3f52'
	d.reset()
	l, hash2 := d.checksum('Hi from V_crypto. This is an example of a long long line.'.bytes())
	assert hash2.hex() == '174fb40500bd3a5dae83c715a4b6528c'
	assert l == 128

	assert hexhash('test') == 'db346d691d7acc4dc2625db19f9e3f52'
	assert hexhash('This version of MD4 is implemented in V') == 'ca8b2573e629e936749d8be2cbdbb717'
}
