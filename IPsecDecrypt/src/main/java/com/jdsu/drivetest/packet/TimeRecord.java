package com.jdsu.drivetest.packet;

public class TimeRecord {
	public int usec;
	public int sec;

	TimeRecord(int s, int us) {
		sec = s;
		usec = us;
	}
	TimeRecord() {
		sec = 0;
		usec = 0;
	}
}
