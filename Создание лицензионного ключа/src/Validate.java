package com.application;

import java.io.*;
import java.security.*;


public class Validate {

    public static final String PRIVATE_KEY_FILE = "private.key";

    public static final String FITXER_PLA = "SignarProva.txt";
    public static final String FITXER_SIGNAT = "SignatProva.txt";

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
        random.nextBytes(key); 
        boolean res = Utils.vetify(f,  prik);
        
        System.out.println("Result of verify key: " + res);

    }

}