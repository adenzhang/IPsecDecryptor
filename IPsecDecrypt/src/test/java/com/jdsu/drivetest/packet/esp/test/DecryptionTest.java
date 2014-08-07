package com.jdsu.drivetest.packet.esp.test;

import com.jdsu.drivetest.ipsec.decrypt.EncryptionAlgorithm;
import com.jdsu.drivetest.packet.Fn;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by jiezhang on 8/7/14.
 */
public class DecryptionTest {
    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        DecryptionTest t = new DecryptionTest();
//		t.test_encrypt();
        t.test_ESP_TransMode();
    }

    /*
     * Case #1: Encrypting 16 bytes (1 block) using AES-CBC with 128-bit key
Key       : 0x06a9214036b8a15b512e03d534120006
IV        : 0x3dafba429d9eb430b422da802c9fac41
Plaintext : "Single block msg"
Ciphertext: 0xe353779c1079aeb82708942dbe77181a

     */
    void test1() {
        byte[] key = new byte[]{ 0x06, (byte)0xa9, 0x21, 0x40, 0x36, (byte)0xb8, (byte)0xa1, 0x5b
                , 0x51, 0x2e, 0x03, (byte)0xd5, 0x34, 0x12, 0x00, 0x06 };
        byte[] iv =  new byte[]{ 0x3d, (byte)0xaf, (byte)0xba, 0x42, (byte)0x9d, (byte)0x9e, (byte)0xb4, 0x30
                , (byte)0xb4, 0x22, (byte)0xda, (byte)0x80, 0x2c, (byte)0x9f, (byte)0xac, 0x41 };
        String txt = "Single block msg";
        byte[] cip = new byte[]{ (byte)0xe3, 0x53, 0x77, (byte)0x9c, 0x10, 0x79, (byte)0xae, (byte)0xb8
                , 0x27, 0x08, (byte)0x94, 0x2d, (byte)0xbe, 0x77, 0x18, 0x1a };

        EncryptionAlgorithm algo = EncryptionAlgorithm.getInstance(EncryptionAlgorithm.Algo.AES_CBC);
        algo.setEncryptionKey(key);

        byte[] deciphered = algo.decrypt(iv, cip, 0, cip.length);
        String s = new String(deciphered);
        System.out.println(s);
    }
    void test_encrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] key = new byte[]{ 0x06, (byte)0xa9, 0x21, 0x40, 0x36, (byte)0xb8, (byte)0xa1, 0x5b
                , 0x51, 0x2e, 0x03, (byte)0xd5, 0x34, 0x12, 0x00, 0x06 };
        byte[] iv =  new byte[]{ 0x3d, (byte)0xaf, (byte)0xba, 0x42, (byte)0x9d, (byte)0x9e, (byte)0xb4, 0x30
                , (byte)0xb4, 0x22, (byte)0xda, (byte)0x80, 0x2c, (byte)0x9f, (byte)0xac, 0x41 };

        String txt = "Single block msg";
        byte[] inplain = EncryptionAlgorithm.addPad(txt, iv.length);
        EncryptionAlgorithm.xor(inplain, 0, inplain, 0, iv);

        //-------- encryption
        Cipher cipher;

        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,  new SecretKeySpec(key, "AES"));

        byte[] ciphered;
        ciphered = cipher.doFinal(inplain);


//		for(int i=0; i<inplain.length; ++i)
//			System.out.print(String.format("%d:%02X ", i,ciphered[i]));

        //-------- decryption
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
//		byte[] decyphered = cipher.doFinal(Arrays.copyOfRange(ciphered, 0, iv.length));
        byte[] decyphered = cipher.doFinal(ciphered);

        EncryptionAlgorithm.xor(decyphered, 0, decyphered, 0, iv);
        System.out.println(new String(decyphered));

//		for(int i=0; i<inplain.length; ++i)
//			System.out.print(String.format("%d:%02X ", i,decyphered[i]));
        return;
    }

    /*******************
     Case #5: Sample transport-mode ESP packet (ping 192.168.123.100)
     Key: 90d382b4 10eeba7a d938c46c ec1a82bf
     SPI: 4321
     Source address: 192.168.123.3
     Destination address: 192.168.123.100
     Sequence number: 1
     IV: e96e8c08 ab465763 fd098d45 dd3ff893

     Original packet:
     IP header (20 bytes): 45000054 08f20000 4001f9fe c0a87b03 c0a87b64
     Data (64 bytes):
     08000ebd a70a0000 8e9c083d b95b0700 08090a0b 0c0d0e0f 10111213 14151617
     18191a1b 1c1d1e1f 20212223 24252627 28292a2b 2c2d2e2f 30313233 34353637

     Augment data with:
     Padding: 01020304 05060708 090a0b0c 0d0e
     Pad length: 0e
     Next header: 01 (ICMP)

     Pre-encryption Data with padding, pad length and next header (80 bytes):
     08000ebd a70a0000 8e9c083d b95b0700 08090a0b 0c0d0e0f 10111213 14151617
     18191a1b 1c1d1e1f 20212223 24252627 28292a2b 2c2d2e2f 30313233 34353637
     01020304 05060708 090a0b0c 0d0e0e01

     Post-encryption packet with SPI, Sequence number, IV:
     IP header: 4500007c 08f20000 4032f9a5 c0a87b03 c0a87b64
     SPI/Seq #: 00004321 00000001
     IV: e96e8c08 ab465763 fd098d45 dd3ff893
     Encrypted Data (80 bytes):
     f663c25d 325c18c6 a9453e19 4e120849 a4870b66 cc6b9965 330013b4 898dc856
     a4699e52 3a55db08 0b59ec3a 8e4b7e52 775b07d1 db34ed9c 538ab50c 551b874a
     a269add0 47ad2d59 13ac19b7 cfbad4a6

     ********************/
    // RFC3602 Sample transport-mode ESP packet
    public void test_ESP_TransMode() {
        //--
        String hexTxt = " 08000ebd a70a0000 8e9c083d b95b0700 08090a0b 0c0d0e0f 10111213 14151617"
                +" 18191a1b 1c1d1e1f 20212223 24252627 28292a2b 2c2d2e2f 30313233 34353637"
                +" 01020304 05060708 090a0b0c 0d0e0e01";

        String hexCiphered = "f663c25d 325c18c6 a9453e19 4e120849 a4870b66 cc6b9965 330013b4 898dc856"
                +"a4699e52 3a55db08 0b59ec3a 8e4b7e52 775b07d1 db34ed9c 538ab50c 551b874a"
                +"a269add0 47ad2d59 13ac19b7 cfbad4a6";
        String hexIV = "e96e8c08 ab465763 fd098d45 dd3ff893";
        String hexKey = "90d382b4 10eeba7a d938c46c ec1a82bf";
        //--
        byte[] txt = Fn.readHex(hexTxt);
        byte[] ciphered = Fn.readHex(hexCiphered);
        byte[] iv = Fn.readHex(hexIV);
        byte[] key = Fn.readHex(hexKey);

//		System.out.println(printHex(iv));
        EncryptionAlgorithm algo = EncryptionAlgorithm.getInstance(EncryptionAlgorithm.Algo.AES_CBC);
        algo.setEncryptionKey(key);
        byte[] deciphered = algo.decrypt(iv,  ciphered, 0, ciphered.length);

        System.out.println(Fn.printHex(deciphered));

    }
}
