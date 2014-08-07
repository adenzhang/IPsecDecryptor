package com.jdsu.drivetest.ipsec.decrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptTrippleDesCbc extends EncryptionAlgorithm {
	public EncryptTrippleDesCbc() {
		super("3DES-CBC", 8, 24);
	}
	@Override
	public byte[] decrypt(byte[] iv, byte[] cipher, int startPos, int len) {
		Cipher c;
		try {
			c = Cipher.getInstance("DESede/CBC/NOPADDING");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		try {
			c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "DESede"), new IvParameterSpec(iv));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		try {
			return c.doFinal(Arrays.copyOfRange(cipher, startPos, startPos+len));
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

}
