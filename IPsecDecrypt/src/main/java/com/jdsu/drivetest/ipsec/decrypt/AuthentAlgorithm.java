package com.jdsu.drivetest.ipsec.decrypt;

public abstract class AuthentAlgorithm {
	public final int resultSize;
	public final int blockSize;
	public final int keyLength;
	public final String name;
	
	protected byte[] authKey;
	
	public static enum Algo {NULL, HMAC_SHA1_96, HMAC_MD5_96}; 
	
	public static final AuthentAlgorithm algoNULL = new AuthentNULL();
	
	public static AuthentAlgorithm getInstance(AuthentAlgorithm.Algo a) {
		switch( a ) {
		case HMAC_SHA1_96:
			return new Auth_HMAC_SHA1_96();
		case HMAC_MD5_96:
			return new Auth_HMAC_MD5_96();
		default:
			return algoNULL;
		}
	}
	
	protected AuthentAlgorithm(String name, int resultSize, int blocksize, int keylength) {
		this.name = name;
		this.resultSize = resultSize;
		blockSize = blocksize;
		keyLength = keylength;
	}
	
	public boolean setAuthentKey(byte[] authKey) {
		if( authKey.length != keyLength ) return false;
		this.authKey = authKey;
		return true;
	}
	public byte[] getAuthentKey() {
		return authKey;
	}
	
	public abstract byte[] generateHash(byte[] cipher, int startPos, int len);
}

class AuthentNULL extends AuthentAlgorithm {
	AuthentNULL() {
		super("NULL", 0, 0, 0);
	}
	public byte[] generateHash(byte[] cipher, int startPos, int len) {
		return null;
	}
}
