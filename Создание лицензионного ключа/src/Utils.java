package com.application;
import javax.crypto.Cipher;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;

import java.io.ObjectOutputStream;
import java.security.*;

public class Utils {
   
    public static boolean areKeysPresent(){
        File privateKey = new File("private.key");
        File publicKey = new File("public.key");

        if(publicKey.exists() && privateKey.exists()){
            return true;
        }else {
            return false;
        }
    }

    
    public static KeyPair generateKey(){
        KeyPair clv = null;
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            clv = gen.genKeyPair();

            PublicKey publicKey = clv.getPublic();
            PrivateKey privateKey = clv.getPrivate();

            File publicKeyFile = new File("public.key");
            publicKeyFile.createNewFile();
            File privateKeyFile = new File("private.key");
            publicKeyFile.createNewFile();

            ObjectOutputStream objOutStream = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
            objOutStream.writeObject(publicKey);

            objOutStream = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
            objOutStream.writeObject(privateKey);
            objOutStream.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return clv;
    }

    
    public static byte[] digestiona(File f, String algoritmo) {
        byte[] fileBytes = new byte[(int) f.length()];
        byte[] res = null;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
             res = md.digest(fileBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }
    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        boolean result = publicSignature.verify(signatureBytes);
        return result;
    }
    public static byte[] sign(byte[] digest, PrivateKey pk){
        byte[] res = null;
        try {
            Cipher key = Cipher.getInstance("RSA");
            key.init(Cipher.ENCRYPT_MODE, pk);
            res = key.doFinal(digest);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return res;
    }
    public static void write(String path , byte[] signatura) throws Exception {
        ObjectOutputStream ou = new ObjectOutputStream(new FileOutputStream(path));
        ou.write(signatura);
        ou.close();
    }
}
