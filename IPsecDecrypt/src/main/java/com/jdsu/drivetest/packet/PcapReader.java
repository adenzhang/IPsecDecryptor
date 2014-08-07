package com.jdsu.drivetest.packet;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;

public class PcapReader implements IPacketReader {

	String filename;
	FileInputStream fin;
	FileChannel    fch;
	ByteBuffer     buf;
	
	@Override
	public boolean open(String url){
		filename = url;
		File file = new File(filename);
		try {
			fin = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		// read file header
		fch = fin.getChannel();
		buf = ByteBuffer.allocate(PcapFileHeader.SIZE);
		try {
			fch.read(buf);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	@Override
	public byte[] read(TimeRecord tr) {
		buf = ByteBuffer.allocate(PcapPacketHeader.SIZE);
		buf.order(ByteOrder.LITTLE_ENDIAN);
		try {
			fch.read(buf);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		buf.rewind();
        int sec = buf.getInt();
        int usec = buf.getInt();
		if( tr != null ) {
			tr.sec = sec;
			tr.usec = usec;
		}
		int len = buf.getInt();
		buf = ByteBuffer.allocate(len);
		try {
			fch.read(buf);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		return buf.array();
	}

	@Override
	public void close() {
		try {
			fch.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			fin.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}

class PcapFileHeader {
    public int     uMagicNumber;        //Magic number (0xa1b2c3d4)
    public char uVerMajor;           //Major version number
    public char uVerMinor;           //Minor version number
    public int uThisZone;           //GMT to local correction
    public int uSigfigs;            //Accuracy of timestamps
    public int uSnaplen;            //Max length of captured packets (byte)
    public int uNetwork;            //Data link type
    public static final int SIZE = 24; // bytes
}
class PcapPacketHeader{
	public int ts_sec;             /* timestamp seconds */                         //This corresponds to timeSecs in RTSM header
	public int ts_usec;            /* timestamp microseconds */                    //This corresponds to timeNSecs/1000 in RTSM header 
	public int incl_len;           /* number of octets of packet saved in file */  //This corresponds to storedLength in RTSM DATA header only
	public int orig_len;           /* actual length of packet */                   //This corresponds to rcvLength in RTSM DATA header only
    public static final int SIZE = 16; // bytes	
}
