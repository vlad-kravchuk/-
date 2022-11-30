package com.application;
import java.io.*;
import java.security.*;


public class Generate {

    public static final String PRIVATE_KEY_FILE = "private.key";

    public static final String FITXER_PLA = "key.txt";
    public static final String FITXER_SIGNAT = "key.txt";

    public static void main(String[] args) throws Exception {

        KeyPair keyPair = null;
        PrivateKey prik = null;

        File f = new File(FITXER_PLA);

        if(!Utils.areKeysPresent()){
            keyPair = Utils.generateKey();
            prik = keyPair.getPrivate();
        }else{
            ObjectInputStream inputStream = null;
            inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
            prik = (PrivateKey) inputStream.readObject();
        }

        byte[] digestionat = Utils.digestiona(f,"MD5");
        Random random = new Random();
        byte[] key = new byte[20];
        random.nextBytes(key); 
        byte[] encryptdigestionat = Utils.sign(digestionat, prik);
        Utils.write(FITXER_SIGNAT,encryptdigestionat, key);
    }

}