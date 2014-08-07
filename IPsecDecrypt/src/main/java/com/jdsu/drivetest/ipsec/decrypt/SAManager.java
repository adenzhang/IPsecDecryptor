package com.jdsu.drivetest.ipsec.decrypt;

import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

/**
 * Created by jiezhang on 8/6/14.
 */
public class SAManager {

    private static final String TAG = SAManager.class.getSimpleName();
    private static final String COMMAND = "ip xfrm state";
    private Map<SA.KeyRecord, SA> db;

    public SAManager() {
        db = new HashMap<SA.KeyRecord, SA>();
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public SA querySA(SA.KeyRecord key) {
        return db.get(key);
    }

    public boolean fromFile(String filename) {
        FileReader fileReader;
        try {
            fileReader = new FileReader(new File(filename));
        }catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        }

        BufferedReader br = new BufferedReader(fileReader);

        List<String> lines = new LinkedList<String>();
        String line = null;

        try {
            while ((line = br.readLine()) != null) {
                lines.add(line);
            }
        }catch (IOException e){
            e.printStackTrace();
            return false;
        }
        update(lines);
        try {
            br.close();

        }catch (IOException e){
            e.printStackTrace();
        }
        return  true;
    }
    public void update(List<String> lines) {

         SA sa = new SA();

        for(String s:lines) {
            String line = s.trim();
            if ( line!=null && line.length() != 0) {
                String[] tokens = line.split(" ");
                for (int index = 0; index < tokens.length; ) {
                    index = parseParameter(sa, tokens, index) + 1;
                }
                if (line.startsWith("sel")) {  // last line of an SA record
                    sa.constructEspDecryption();
                    db.put(sa.key, sa);
                    sa = new SA();
                }
            }
        }
    }

    @Override
    public String toString() {
        return "SAManager{" +
                "db=" + db +
                '}';
    }

    private int parseParameter(SA sa, String[] tokens, int currentPosition) {
        if (tokens[currentPosition].equalsIgnoreCase("src")) {
            try {
                currentPosition++;
                sa.strSrcIP = tokens[currentPosition];
                sa.key.srcIP = InetAddress.getByName(tokens[currentPosition]).getAddress();
            } catch (UnknownHostException e) {
                e.printStackTrace();
            }
        } else if (tokens[currentPosition].equalsIgnoreCase("dst")) {
//            try {
                currentPosition++;
                sa.strDstIP = tokens[currentPosition];
//                sa.key.dstIP = InetAddress.getByName(tokens[currentPosition]).getAddress();
//            } catch (UnknownHostException e) {
//                e.printStackTrace();
//            }
        } else if (tokens[currentPosition].equalsIgnoreCase("proto")) {
            currentPosition++;
            sa.protocol = tokens[currentPosition];
        } else if (tokens[currentPosition].equalsIgnoreCase("spi")) {
            currentPosition++;
            sa.key.spi = hexStringToByteArray(tokens[currentPosition].substring(2));
        } else if (tokens[currentPosition].equalsIgnoreCase("reqid")) {
            currentPosition++;
            sa.requestId = Integer.parseInt(tokens[currentPosition]);
        } else if (tokens[currentPosition].equalsIgnoreCase("mode")) {
            currentPosition++;
            sa.mode = SA.Mode.fromAlias(tokens[currentPosition]);
        } else if (tokens[currentPosition].equalsIgnoreCase("auth-trunc")) {
            currentPosition++;
            sa.authAlgorithm = SA.toAuthAlgo(tokens[currentPosition]);
            if (sa.authAlgorithm != AuthentAlgorithm.Algo.NULL) {
                currentPosition++;
                sa.authKey = tokens[currentPosition];
            }
        } else if (tokens[currentPosition].equalsIgnoreCase("enc")) {
            currentPosition++;
            sa.encryptionAlgorithm = SA.toEncryptionAlgo(tokens[currentPosition]);
            if (sa.encryptionAlgorithm != EncryptionAlgorithm.Algo.NULL) {
                currentPosition++;
                sa.encryptionKey = tokens[currentPosition];
            }
        } else {
            currentPosition++;
        }
        return currentPosition;
    }
}