package com.jdsu.drivetest.ipsec.decrypt;

public class Auth_HMAC_MD5_96 extends AuthentAlgorithm {

	
	public Auth_HMAC_MD5_96() {
		super("HMAC-MD5-96", 12, 64, 20);
	}
	public Auth_HMAC_MD5_96(byte[] authKey) {
		super("HMAC-MD5-96", 12, 64, 20);
		setAuthentKey(authKey);
	}
	@Override
	public byte[] generateHash(byte[] cipher, int startPos, int len) {
		// TODO Auto-generated method stub
		return null;
	}

}
