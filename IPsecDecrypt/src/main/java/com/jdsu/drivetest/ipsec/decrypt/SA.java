package com.jdsu.drivetest.ipsec.decrypt;

import com.jdsu.drivetest.packet.esp.DecryptEspPacket;

import java.net.InetAddress;
import java.util.Arrays;

/**
 * Created by jiezhang on 8/6/14.
 */
public class SA {
    public static class KeyRecord {
        public byte[] srcIP;
//        public byte[] dstIP;
        public byte[] spi;

        public KeyRecord() {}
        public KeyRecord(byte[] src, byte[] spi) {
            this.spi = spi;
            srcIP = src;
//            dstIP = dst;
        }
        @Override
        public int hashCode() {
            int result = Arrays.hashCode(srcIP);
            result = 31 * result + Arrays.hashCode(spi);
            return result;
        }
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof KeyRecord)) return false;

            KeyRecord k = (KeyRecord) o;

            if (!Arrays.equals(srcIP, k.srcIP)) return false;
//            if (!Arrays.equals(dstIP, k.dstIP)) return false;
            if (!Arrays.equals(spi, k.spi)) return false;

            return true;
        }
    }

    KeyRecord     key;
    String        strSrcIP, strDstIP;
    public String protocol;
    public int requestId;
    public Mode mode;
    public int replay_window;
    public  AuthentAlgorithm.Algo authAlgorithm;
    public String authKey;
    public EncryptionAlgorithm.Algo encryptionAlgorithm;
    public String encryptionKey;

    public DecryptEspPacket espDecryption;

    public SA() {
        key = new KeyRecord();
    }
    public void constructEspDecryption() {
        espDecryption = new DecryptEspPacket(encryptionKey, authKey, encryptionAlgorithm, authAlgorithm);
    }
    @Override
    public String toString() {
        return "SA{" +
                "src=" + strSrcIP +
                ", dst=" + strDstIP +
                ", protocol='" + protocol + '\'' +
                ", spi=" + Arrays.toString(key.spi) +
                ", requestId=" + requestId +
                ", mode=" + mode +
                ", replay_window=" + replay_window +
                ", authAlgorithm=" + authAlgorithm +
                ", authKey=" + authKey +
                ", encryptionAlgorithm=" + encryptionAlgorithm +
                ", encryptionKey=" + encryptionKey +
                '}';
    }

    public enum Mode {
        TRANSPORT, TUNNEL;

        public static Mode fromAlias(String alias) {
            if (alias.equalsIgnoreCase("transport")) {
                return TRANSPORT;
            } else if (alias.equalsIgnoreCase("tunnel")) {
                return TUNNEL;
            }
            return null;
        }
    }

    public static AuthentAlgorithm.Algo toAuthAlgo(String alias) {
        if (alias.equalsIgnoreCase("hmac(md5)")) {
            return AuthentAlgorithm.Algo.HMAC_MD5_96;
        } else if (alias.equalsIgnoreCase("hmac(sha1)")) {
            return AuthentAlgorithm.Algo.HMAC_SHA1_96;
        } else if (alias.contains("null")) {
            return AuthentAlgorithm.Algo.NULL;
        }
        return null;
    }

    public static EncryptionAlgorithm.Algo toEncryptionAlgo(String alias) {
        if (alias.equalsIgnoreCase("cbc(aes)")) {
            return EncryptionAlgorithm.Algo.AES_CBC;
        } else if (alias.equalsIgnoreCase("cbc(des3_ede)")) {
            return EncryptionAlgorithm .Algo.TRIPPLE_DES_CBC;
        } else if (alias.contains("null")) {
            return EncryptionAlgorithm .Algo.NULL;
        }
        return null;
    }
}
