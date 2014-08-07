package com.jdsu.drivetest.packet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class Fn {
	public static byte[] readHex(String txt) throws NumberFormatException {
		boolean bHexHead = false;
		int N = txt.length(); 
		byte[] buf = new byte[N/2];
		int k = 0;
		int m = 0; // length if bytes
		while( k < N ) {
			char ch = txt.charAt(k);
			if( ch == ' ' || ch == '\n') {
				k++;
				continue;
			}
			String ts = txt.substring(k, k+2);
			if( 0 == ts.compareToIgnoreCase("0x") ) {
				k += 2;
				continue;
			}
			int ti = Integer.decode("0x" + ts);
			buf[m++] = (byte) ti;
			k += 2;
		}
		return Arrays.copyOf(buf, m);
	}
	public static String printHex(byte[] b) {
		String s = "";
		for(int i = 0 ; i<b.length; ++i) {
			if( i%4 == 0 && i>1) 
				s += " ";
			if( i%16 == 0 && i>1) 
				s += "\n";
			s = s+ String.format("%02X", b[i]);
		}
		return s;
	}
	public static int locateIp(byte[] packet) {
		return 16;
	}

    public static class IpInfo {
        public int posIP;
        public int posPayload;
        public int lenPayload;
        public int ipVer;
        public byte[] src;
        public byte[] dest;
    }
    // return srcPos, destPos, addressLen;
    public static boolean setIpInfo(byte[] packet, IpInfo info) {
        info.posIP = locateIp(packet);
        ByteBuffer buf = ByteBuffer.wrap(packet, info.posIP, packet.length - info.posIP);
        buf.order(ByteOrder.BIG_ENDIAN);
        byte bb = buf.get();
        int ipVer = bb >> 4;
        info.ipVer = ipVer;
        int headerLen = 0;
        if( ipVer == 4 ) {
            info.src = Arrays.copyOfRange(packet, info.posIP + 12, info.posIP + 12 + 4);
            info.dest = Arrays.copyOfRange(packet, info.posIP + 16, info.posIP + 16 + 4);
            headerLen = (bb & 0x0F) << 2;
            info.posPayload = info.posIP + headerLen;

            buf.get(); // DSCP, ECN
            int iplen = buf.getChar(); // total length
            info.lenPayload = iplen - headerLen;
        }else {
            info.src = Arrays.copyOfRange(packet, info.posIP + 8, info.posIP + 8 + 16);
            info.dest = Arrays.copyOfRange(packet, info.posIP + 24, info.posIP + 24 + 16);
            headerLen = 40;
            info.posPayload = info.posIP + headerLen;
            buf.get();  //traffic class
            buf.getChar(); //flow label
            info.lenPayload = buf.getChar(); // payload length
        }
        return true;
    }

	// return int[] : 0:payloadPosition, 1:payloadSize
	public static int[] locateIpPayload0(byte[] packet, int ipPos) {
		ByteBuffer buf = ByteBuffer.wrap(packet, ipPos, packet.length - ipPos);
		buf.order(ByteOrder.BIG_ENDIAN);
		byte bb = buf.get();
		int ipVer = bb >> 4;
		int[]  ret = new int[2];
		int headerLen = 0;
		if( ipVer == 4 ) {
			headerLen = (bb & 0x0F) << 2;
			ret[0] = ipPos + headerLen;
			
			buf.get(); // DSCP, ECN
			int iplen = buf.getChar(); // total length
			ret[1] = iplen - headerLen; 
		}else {
			headerLen = 40;
			ret[0] = ipPos + headerLen;
			buf.get();  //traffic class
			buf.getChar(); //flow label
			ret[1] = buf.getChar(); // payload length
		}
		return ret;
	}
}
