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

public class EncryptAesCbc extends EncryptionAlgorithm {
	
	public EncryptAesCbc() {
		super("AES-CBC", 16, 16);
	}
	@Override
	public boolean setEncryptionKey(byte[] key) {
		super.setEncryptionKey(key);
		decryptFunc = new AesDecrypt(key);
		return true;
	}
	@Override
	public byte[] decrypt(byte[] iv, byte[] cipher, int startPos, int len) {
		Cipher c;
		try {
			c = Cipher.getInstance("AES/CBC/NOPADDING");
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
			c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(iv));
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

	static class AesDecrypt implements EncryptionFunction {
		byte[] encKey;
		Cipher cipher;
		public AesDecrypt(byte[] key) {
			encKey = key;
			try {
				cipher = Cipher.getInstance("AES");
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			try {
				cipher.init(Cipher.DECRYPT_MODE,  new SecretKeySpec(encKey, "AES"));
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		@Override
		public byte[] apply(byte[] ciphered) {
			try {
				return cipher.doFinal(ciphered);
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
}
