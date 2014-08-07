package com.jdsu.drivetest.packet;

import java.io.PrintStream;
import java.sql.Time;
import java.util.Arrays;

import com.jdsu.drivetest.ipsec.decrypt.AuthentAlgorithm;
import com.jdsu.drivetest.ipsec.decrypt.EncryptionAlgorithm;
import com.jdsu.drivetest.ipsec.decrypt.SA;
import com.jdsu.drivetest.ipsec.decrypt.SAManager;
import com.jdsu.drivetest.packet.esp.DecryptEspPacket;

public class SimplePcapReader {
    Fn.IpInfo          ipInfo;
    static final int   lenSPI = DecryptEspPacket.ESP_SPI_SIZE;
    SA.KeyRecord       key;
    String             saFile;
    String             pcapFile;
    PcapReader         pcap;
    SAManager          samgr;
    SA                 sa;

    public SimplePcapReader(String safile, String pcapfile) {
        ipInfo = new Fn.IpInfo();
        key = new SA.KeyRecord();
        key.spi = new byte[lenSPI];

        saFile = safile;
        pcapFile = pcapfile;
    }
    public boolean open() {
        samgr = new SAManager();
        samgr.fromFile(saFile);

        pcap = new PcapReader();
        if( !pcap.open(pcapFile) )
            return false;
        return true;
    }
    public void close() {
        pcap.close();
    }
    public int skipPackets(int k) {
        int i = 0;
        for(i=0; i<k;++i) {
            if( null == pcap.read(null) )
                break;
        }
        return i;
    }
    public byte[] nextPacket(TimeRecord tr) {
        byte[] packet = pcap.read(tr);
        if( packet == null ) return null;

        Fn.setIpInfo(packet, ipInfo);
        key.srcIP = ipInfo.src;
        System.arraycopy(packet, ipInfo.posPayload, key.spi, 0, lenSPI);
        sa = samgr.querySA(key);
        if( sa == null )
            return packet;
        sa.espDecryption.setPacket(packet, ipInfo);
        sa.espDecryption.decrypt();
        return packet;
    }
    public static void decryptPcap(PrintStream out, String safile, String pcapfile, int skipPackets, int nPackets) {
        SimplePcapReader pr = new SimplePcapReader(safile, pcapfile);
        if(!pr.open()) {
            out.println("Failed to open pcap file");
            return;
        }
        // skip
        if( pr.skipPackets(skipPackets) < skipPackets)
            return;

        TimeRecord tr =  new TimeRecord();
        for(int i=0; i< nPackets; ++i) {
            byte[] packet = pr.nextPacket(null);
            if( packet == null ) {
                out.println("*** EOF");
            }
            byte[] deciphered;
            if( pr.sa == null ) {
                deciphered = Arrays.copyOfRange(packet, pr.ipInfo.posPayload, pr.ipInfo.posPayload + pr.ipInfo.lenPayload);
                out.printf("-- %d Non Decrypted ESP ");
            }else {
                int posEspDecrypt = pr.ipInfo.posPayload + DecryptEspPacket.ESP_HEADER_SIZE + pr.sa.espDecryption.blockSize;
                int lenEspDecrypt = pr.ipInfo.lenPayload - DecryptEspPacket.ESP_HEADER_SIZE - pr.sa.espDecryption.authResultSize - pr.sa.espDecryption.blockSize;
                deciphered = Arrays.copyOfRange(packet, posEspDecrypt, posEspDecrypt + lenEspDecrypt);
                out.printf("-- %d Decrypted ESP from:%d, len:%d --\n", skipPackets + i + 1, posEspDecrypt, lenEspDecrypt);
            }
            out.println(Fn.printHex(deciphered));
        }
        pr.pcap.close();
    }

    public static void main(String[] args) {

        test_readPcap_DecryptESP();
    }
    public static void test_readPcap_DecryptESP() {
        String safile = "/data/pcap/esp_sa.txt";
        String pcapfile = "/data/pcap/encrypted.pcap";
        int    skipPackets = 2;
        SimplePcapReader.decryptPcap(System.out, safile, pcapfile, skipPackets, 3);
    }
}
