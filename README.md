IPsecDecrytor

Decrypt ESP packt with SA.

Created by Zhang Jie on Aug 7 2014.

-----------------------
Developed in Android Studio, this project has two modules: java library IPsecDecrypt and android application app.

-- 
Module IPsecDecrypt:
	A java library provides common classes to read pcap file and decrypt ESP packets. SA files should be given for decryption.
	Below  are all potentially supported decryption algorithms.
1.	AES-CBC (tested already)
2.	AES-CTR.
3.	3DES-CBC.
4.	DES-CBC.
5.	CAST5-CBC.
6.	BLOWFISH-CBC.
7.	TWOFISH-CBC.
8.	AES-GSM.
	

Module app: 
	Android applciation to demo decryption.

--
v0.1
What Done:
	- pcap reader.
	- IP info parser.
	- Decryption framwework.
	- SA file reader.
	- SA manager to store SA's.
	- Algorithms: AES-CBC, 3DES-CBC (not tested yet).

TODO:
	- pcap write.
	- SA generation on rooted phones.
	- Implement more decryption algorithms.


