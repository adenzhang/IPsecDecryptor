package com.jdsu.drivetest.ipsec.decrypt;

public interface EncryptionFunction {
    byte[] apply(byte[] cipher);
}
