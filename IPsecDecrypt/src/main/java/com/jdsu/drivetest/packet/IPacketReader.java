package com.jdsu.drivetest.packet;


public interface IPacketReader {

	boolean open(String url);
	
	byte[] read(TimeRecord tr);
	
	void close();
}
