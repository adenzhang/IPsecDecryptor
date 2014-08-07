package com.jdsu.drivetest.ipsec.decrypt;

public class EncryptionAlgorithm {
	public final int blockSize;
	public final int keyLength;
	public final String name;
	public byte[]     encKey;
	protected EncryptionFunction  decryptFunc;


	public static enum Algo {NULL, AES_CBC, TRIPPLE_DES_CBC};
	
	public static final EncryptionAlgorithm algoNULL = new EncryptNull();

	public static EncryptionAlgorithm getInstance(EncryptionAlgorithm.Algo algo) {
		switch( algo ) {
		case AES_CBC:
			return new EncryptAesCbc();
		case TRIPPLE_DES_CBC:
			return new EncryptTrippleDesCbc();
		default:
			return algoNULL;			
		}
	}
	protected EncryptionAlgorithm(String name, int blocksize, int keylength) {
		this.name = name;
		blockSize = blocksize;
		keyLength = keylength;
	}
	public boolean setEncryptionKey (byte[] encKey) {
		if( encKey.length != keyLength ) return false;
		this.encKey = encKey;
		return true;
	}
	public byte[] getEncryptionKey() {
		return encKey;
	}

	public byte[] decrypt(byte[] iv, byte[] cipher, int startPos, int len) {
		byte[] deciphered = new byte[len];
		System.arraycopy(cipher, 0, iv, 0, blockSize);
		
		int ok = DecipherBlockChain(decryptFunc, iv, cipher, 0, deciphered, 0, len);
		if( ok > 0)
			return deciphered;
		else
			return null;
	}
    public boolean decryptInplace(byte[] iv, byte[] cipher, int startPos, int len) {
        byte[] deciphered = decrypt(iv, cipher, startPos, len);
        if( deciphered != null && deciphered.length > 0 ) {
            System.arraycopy(deciphered, 0, cipher, startPos, len);
            return true;
        }
        return false;
    }
	static public boolean detectNull(byte[] cipher, int startPos, int len) {
		return EncryptNull.detectNull(cipher, startPos, len);
	}

    // @return length of output text, -1 for error
    static protected int DecipherBlockChain(EncryptionFunction fn, byte[] iv, byte[] cipher, int istartpos, byte[] output, int ostartpos, int len) {
        int n = 0;
        int blockSize = iv.length;
        byte[] inbuf = new byte[blockSize];
        byte[] outbuf;

        // decrypt the first block and XOR with IV.
        System.arraycopy(cipher, istartpos, inbuf, 0, blockSize);
        outbuf = fn.apply(inbuf);
        if( outbuf == null ) 
        	return -1;
        for(int i=0; i<blockSize; ++i)
        	outbuf[i] ^= iv[i];
        System.arraycopy(outbuf, 0, output, ostartpos, blockSize);

        // decrypt rest
        n += blockSize;
        for(; n < len; n += blockSize ) {
        	System.arraycopy(cipher, istartpos+n, inbuf, 0, blockSize);
            outbuf = fn.apply(inbuf);
            if( outbuf == null ) 
            	return -1;
            for(int i=0; i<blockSize; ++i)
            	outbuf[i] ^= cipher[istartpos+n-blockSize+i];
            System.arraycopy(outbuf, 0, output, ostartpos+n, blockSize);
        }
        return n == len ? -1: n;
    }
	static public byte[] addPad(byte[] txt, int nbytes) {
		int n = txt.length;
		int npad = n%nbytes;
		if( npad != 0 ) 
			npad = nbytes - npad;
		n += npad;
		byte[] result = new byte[n];
		System.arraycopy(txt, 0, result, 0, txt.length);
		return result;
	}
	static public byte[] addPad(String txt, int nbytes) {
		return addPad(txt.getBytes(), nbytes);
	}
	static public void xor(byte[] result, int startPos, byte[] x, int startPosX, byte[] y) {
		for(int i=0; i < y.length; ++i) {
			result[startPos+i] = (byte) (x[startPosX+i] ^ y[i]);
		}
	}

}

