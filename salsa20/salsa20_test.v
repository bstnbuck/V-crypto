module salsa20

import encoding.hex

fn test_salsa20() {
	rounds := 20

	key0 := hex.decode('0000000000000000000000000000000000000000000000000000000000000000')!
	nonce0 := hex.decode('0000000000000000')!
	counter0 := u64(3247723)
	plain0 := hex.decode('766572792073686f7274206d7367')! // very short msg
	out0 := hex.decode('d3da269f15932b29ebd6766d0d0c')!

	key1 := hex.decode('0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D')!
	nonce1 := hex.decode('0D74DB42A91077DE')!
	counter1 := u64(277372)
	plain1 := hex.decode('766572792073686f7274206d7367')! // very short msg
	out1 := hex.decode('839fa746598ab737b6da80bd9efd')!

	key2 := hex.decode('0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12')!
	nonce2 := hex.decode('167DE44BB21980E7')!
	plain2 := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".bytes()
	out2 := '752592b5faf69149665c59ba94fe83b281685f699c66ef4d25b80c2bb7b62bb2750f7121f3f74856ba89fdbe7e2440e68173f81221a7397c42d0d7172ad38ae8cb9cb3be071c61604670d8e8feabfd5da0b34ce064ff578f64e9e1d4395d4f7ad6736bf54d8fb69345cc76f8ac4b828c86d4'

	key3 := hex.decode('0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417')!
	nonce3 := hex.decode('1F86ED54BB2289F0')!
	counter3 := u64(1)
	plain3 := hex.decode('4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e')!
	out3 := hex.decode('99ce04e94e1c872f514e7dfa2acd8cdb0b6c49878a553167cd003286539927597e01b2eb27cd4b1548935c01cb366dd289c69c582f504b92dbc4aa29b718d87568a04aa31d17ff5098adc2ef04bb2157f04a46171e7009f807b9eef7d6d685c46c546b089bc124c38013f072ab44d73e2471')!

	key4 := hex.decode('0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C')!
	nonce4 := hex.decode('288FF65DC42B92F9')!
	counter4 := u64(4)
	rounds4 := 8
	plain4 := hex.decode('4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e')!
	out4 := hex.decode('053c1b45f912a1ec5740f06d4c9d6e6a7274c1360c7f085cad5e9e354aac25c76c21af7f819bf76da578d0af14667215e36113f533db3e6df841cd2201cc4d7ff6240409ddb43dfa4c06233c73e440eacfe22d787e52749275e117e7c9d4dac5fdf40e66bce91c9b4a438dff12d01f02eb3a')!

	// test0: check zeroed key + nonce and set_counter
	//
	mut c0 := new_cipher(key0, nonce0)!
	c0.set_counter(counter0)
	mut enc0 := []u8{len: plain0.len}
	c0.xor_key_stream(mut enc0, plain0)
	assert enc0 == out0

	mut dec0 := []u8{len: plain0.len}
	c0.rekey(key0, nonce0, counter0, rounds)!
	c0.xor_key_stream(mut dec0, enc0)
	assert dec0 == plain0

	// test1: check manual encryption/decryption
	//
	mut c1 := new_cipher(key1, nonce1)!
	mut enc1 := []u8{len: plain1.len}
	c1.xor_key_stream(mut enc1, plain1)
	assert enc1 == out1

	mut dec1 := []u8{len: plain1.len}
	c1.rekey(key1, nonce1, 0, rounds)!
	c1.xor_key_stream(mut dec1, enc1)
	assert dec1 == plain1

	// test2: check encryption/decryption function
	//
	enc2 := encrypt(key2, nonce2, plain2)!
	assert enc2.hex() == out2
	dec2 := decrypt(key2, nonce2, enc2)!
	assert dec2 == plain2

	// test3: check encryption/decryption with different counter, rekeying
	//
	mut c3 := new_cipher(key1, nonce1)!
	c3.set_counter(counter1)
	c3.rekey(key3, nonce3, counter3, rounds)!
	mut enc3 := []u8{len: plain3.len}
	c3.xor_key_stream(mut enc3, plain3)
	assert enc3 == out3

	mut dec3 := []u8{len: plain3.len}
	c3.rekey(key3, nonce3, counter3, rounds)!
	c3.xor_key_stream(mut dec3, enc3)
	assert dec3 == plain3

	// test4: check encryption/decryption with different counter and rounds, rekeying
	//
	mut c4 := new_cipher(key4, nonce4)!
	c4.set_counter(counter4)
	c4.rekey(key4, nonce4, counter4, rounds4)!
	mut enc4 := []u8{len: plain4.len}
	c4.xor_key_stream(mut enc4, plain4)
	assert enc4 == out4

	mut dec4 := []u8{len: plain4.len}
	c4.rekey(key4, nonce4, counter4, rounds4)!
	c4.xor_key_stream(mut dec4, enc4)
	assert dec4 == plain4

	key5 := hex.decode('0F62B5085BAE0154A7FA4DA0F34699EC3F92E5388BDE3184D72A7DD02376C91C')!
	nonce5 := hex.decode('0D74DB42A91077DE')!
	counter5 := u64(4199997265)
	rounds5 := 12
	plain5 := hex.decode('5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e5468652064686f6c65202870726f6e6f756e6365642022646f6c65222920697320616c736f206b6e6f776e2061732074686520417369617469632077696c6420646f672c2072656420646f672c20616e642077686973746c696e6720646f672e2049742069732061626f7574207468652073697a65206f662061204765726d616e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c757369766520616e6420736b696c6c6564206a756d70657220697320636c6173736966696564207769746820776f6c7665732c20636f796f7465732c206a61636b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d69632066616d696c792043616e696461652e')!
	out5 := hex.decode('6b90f94b3fc318eda5a967a9e9364d8262878bc757bc5777e8c5a3ec803b4b39abb2f12ba90398f0fc7d1ddf2fd092f6b7ac9e9edd06b708fa64f7200ed9a354086c84dc00d54c6c11f7099aaed304ee19035db8a2080bfaf08b2ec98d7a1857925f7407c08fe5ba405d1fbcf97f926b442edda05d18c362237398704915d298aa192d2552cca6bfe2e3e91779d6ebce54d87a6f685e58a44b62d7a278d55f7f6ae23cebd3d65dc9d26b5f5c5c6b382051526e42f7b60cc2967e57b366b4bea13890188e9168f9ec1c5115f1dac139e7c35c2a88e5ab9a45d9fc05b55d8babbe0ffcda85f7e167042d3187d33d0a6ec9a6772afba0c2083ce3dc95a9012089a55d62ebc3ce3567b788577e52158029f1024057057e7e2beb87d908fe5d437997bddd834fdec054b94a9499272889f2cf757656065c80c616d2f5af740a6ae71a1b894e3597b11ca2971aafb6c6db4851c23cd61b659ff3d6429be73a47f89df4adc4abebcf071c800f67af6cb83a1dd73fc909cc70954e3fad4b8941c886634038964da54eaa2b841afbd57a836beb99b06ae1defe575de17bf8b4e4ddcdf0aacd4c98a97718e5e5fc227e2af9d47dfc8b0cbeb878d43b8856601078a813008509b0282c50d6a4129003c66103bd4b4070ec46b3e64499e010eee46b6ebc51cdb5e4e25834156a08ce547a08df7f6039dcc9ba6c03a1099277e9c56bf76e59e2e6565500ae2bb35276d672d7d819e33ab3ca8c09a652d664d472ba32b65e9f1d98e29b45ec42d807351ba82d6be9902bca0ad146a07fb4a6a0719fd6fde4086fbb0cf9d682f86b18c38186d75d3c1e221f138f30bdc1b63410e436969eaf89d7950597cecf291dab71156e88aa328fa844ba523990d859e8b0f0c79df61344c5771a7a1a16d6a3f34b56dacba6e40aa121186661ab061301eafa981cf60eb5edaf0a8c8be46f0416a8f81066d50b09eb975c1f5277ec97032468c125defa61f4ef739ae59784881a41ea5b15dc3760cc6681bfe2e6b61d3017592c6e0ae10d90d30a0a4d0aa68f37791fca0f836dd6df1faa489c94b1b45a1d333bec6ae7bc2f2a230ff9e4e44a30326998709bd2b9126ea77ea2407595b0171ce347d187507608e6689f7cd43feb3ca1780efd5694f571e2f1c74fbcd474600d45ec70e78c6e31ffd868e3e3c182be116d64810450687839bf8eb41b3eed23b30c2a7d4d4947665fa4557248d4a972c28f974af90f1e94340b864945acc79f26f5e7e1973f2c61ea6a909b1fa4f8615aed7f4218dac5ed07e38c0937dd04bf413d5044e4a19c7ee1dd13c0aef6fabac2a183626902aab9a80b9e95b419f376346494944a6fed5d186a68386f135463d5ec1ac731c73662ca020819bbb571119ffd8155af5d821d7bc81e359376335e1298793e38fdbdfb24dcef36a7474d98371d4be8790ecfbd9bf65e430e04e37e82d7f63200837052f840d5967f94c3e757b7c597b20d39f4e19fab8a70fc2392673aa75c368d9eb57c1bdfbd57b5227483e392712fd7452fc323e021d3f51f2ff61e254f57e87da923d078236850f9d0d7b942534713e4cd2a7181b8258eac7e95fd07bcaad8f090de5912f6fde468ff438ab2b1ff337364701e1669277148115c5d4b5776c927c994fba9e362541b2949ad8f51ed87307569b85e40c384595d13abca0fb2e8dae8818ff3f9991d2dbaba00eeb5128b0e')!

	// test5: check encryption/decryption with with high counter value and 12 rounds with big input
	//
	mut c5 := new_cipher(key5, nonce5)!
	c5.rekey(key5, nonce5, counter5, rounds5)!
	mut enc5 := []u8{len: plain5.len}
	c5.xor_key_stream(mut enc5, plain5)
	assert enc5 == out5

	mut dec5 := []u8{len: plain5.len}
	c5.rekey(key5, nonce5, counter5, rounds5)!
	c5.xor_key_stream(mut dec5, enc5)
	assert dec5 == plain5
}