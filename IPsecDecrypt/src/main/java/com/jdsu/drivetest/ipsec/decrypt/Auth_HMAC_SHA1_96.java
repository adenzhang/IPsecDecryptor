package com.jdsu.drivetest.ipsec.decrypt;

public class Auth_HMAC_SHA1_96 extends AuthentAlgorithm {

	Auth_HMAC_SHA1_96() {
		super("HMAC-SHA1-95", 12, 64, 20);
	}
	@Override
	public byte[] generateHash(byte[] cipher, int startPos, int len) {
		// TODO Auto-generated method stub
		return null;
	}

}
