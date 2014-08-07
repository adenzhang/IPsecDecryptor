package com.jdsu.drivetest.packet.esp;

import java.util.Arrays;

import com.jdsu.drivetest.ipsec.decrypt.AuthentAlgorithm;
import com.jdsu.drivetest.ipsec.decrypt.EncryptionAlgorithm;
import com.jdsu.drivetest.packet.Fn;

public class DecryptEspPacket {
	EncryptionAlgorithm decryptAlgo;
	AuthentAlgorithm authAlgo;
	
	public byte[] packet;
    public Fn.IpInfo ipInfo;

	public final int    authResultSize;
	public final int    blockSize;
	
	public static final int ESP_HEADER_SIZE = 8;
    public static final int ESP_SPI_SIZE = 4;

	public DecryptEspPacket(String encKey, String authKey, EncryptionAlgorithm.Algo eDecAlgo, AuthentAlgorithm.Algo eAuthAlgo) {
		decryptAlgo = EncryptionAlgorithm.getInstance(eDecAlgo);
		authAlgo = AuthentAlgorithm.getInstance(eAuthAlgo);
		decryptAlgo.setEncryptionKey(Fn.readHex(encKey));
		authAlgo.setAuthentKey(Fn.readHex(authKey));

		authResultSize = authAlgo.resultSize;
		blockSize = decryptAlgo.blockSize;
}
	public DecryptEspPacket(EncryptionAlgorithm algo, AuthentAlgorithm algoAuth) {
		decryptAlgo = algo;
		authAlgo = algoAuth;
		authResultSize = authAlgo.resultSize;
		blockSize = decryptAlgo.blockSize;
	}
    public void setPacket(byte[] packt) {
		packet = packt;
        if(ipInfo == null)
            ipInfo = new Fn.IpInfo();
		Fn.setIpInfo(packet, ipInfo);
	}
    public void setPacket(byte[] packt, Fn.IpInfo info) {
        packet = packt;
        ipInfo = info;
    }
    public void setPacket(byte[] packt, int aPosIP) {
		packet = packt;
        if(ipInfo == null)
            ipInfo = new Fn.IpInfo();
        Fn.setIpInfo(packet, ipInfo);
	}
    public void decrypt(byte[] packt) {
        setPacket(packt);
        decrypt();
    }
	public void decrypt() {

		int espPayloadPos = ipInfo.posPayload + ESP_HEADER_SIZE;
		int espEncryptSize = ipInfo.lenPayload - ESP_HEADER_SIZE - authResultSize;
		
		byte[] iv = Arrays.copyOfRange(packet, espPayloadPos, espPayloadPos+blockSize);
//		System.out.println("-- IV:" + Integer.toString(iv.length));
//		System.out.println(Fn.printHex(iv));
		decryptAlgo.decryptInplace(iv,  packet, espPayloadPos+blockSize, espEncryptSize-blockSize);
	}

	public byte[] removePadding(byte[] decrypted) {
		int padLen = decrypted[decrypted.length-2];
		
		return Arrays.copyOfRange(decrypted, 0, decrypted.length - (padLen+2));
	}
}
