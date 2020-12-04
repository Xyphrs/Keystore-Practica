package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) throws Exception {

        //Descomenta la linea del ejercicio que quieras ejecutar.


//        Ejercicio1_1();
//        Ejercicio1_2();
//        Ejercicio1_2_1();
//        Ejercicio1_3();
//        Ejercicio1_4();
//        Ejercicio1_5();
//        Ejercicio1_6();

//        Ejercicio2_1();
        Ejercicio2_2();

    }

        // Ejercicio 1.1 -------------------------------------------------------------------------//
        private static void Ejercicio1_1() throws Exception {

        KeyPair keyPair = Methods.randomGenerate(1024);
        Path path = Paths.get("D:\\Downloads\\cifrartest.txt");
        byte[] msg = Files.readAllBytes(path);
        byte[] Cifrado;

        Cifrado = Methods.encryptData(msg, keyPair.getPublic());

        byte[] msgDescifrado = Methods.decryptData(Cifrado, keyPair.getPrivate());

        System.out.println(new String(msgDescifrado, StandardCharsets.UTF_8));
    }

        // Ejercicio 1.2 -------------------------------------------------------------------------//
        private static void Ejercicio1_2() throws Exception {

            KeyStore keystore = Methods.loadKeyStore("C:\\Users\\danvu\\IdeaProjects\\Private Key\\test.keystore", "keystore");
            System.out.println("Type: " + keystore.getType());
            System.out.println("Size: " + keystore.size());
            System.out.println("Aliases: " + keystore.aliases());
            System.out.println("Cert: -----------------------\n " + keystore.getCertificate("keystore"));
            System.out.println("-----------------------------");
            System.out.println("Algoritme: " + keystore.hashCode()); //No se hacer esto del Algoritme

        }

        // Ejercicio 1.2.1 -------------------------------------------------------------------------//
        private static void Ejercicio1_2_1() throws Exception {
            KeyStore keystore = Methods.loadKeyStore("C:\\Users\\danvu\\IdeaProjects\\Private Key\\test.keystore", "keystore");
            SecretKey sKey = Methods.keygenKeyGeneration(128);
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(sKey);
            String password = "Hola";
            KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(password.toCharArray());
            keystore.setEntry("key", secretKeyEntry, protectionParameter);

            System.out.println(keystore.isKeyEntry("key"));
        }

        // Ejercicio 1.3 -------------------------------------------------------------------------//
        private static void Ejercicio1_3() throws Exception {

            File file = new File("certificate.cer"); //Certificate of Public Key "Keystore"
            System.out.println(Methods.getPublicKeyEj3(file)); // No lo he hecho con string en el method, es lo mismo si pones File. Solo que con el string tendrías que definir el path del File dentro del método.

        }

        // Ejercicio 1.4 -------------------------------------------------------------------------//
        private static void Ejercicio1_4() throws Exception {

            // Hay que crear la Clave Asimetrica para que salga bien (keytool -genkeypair -alias test -keyalg DSA -keystore test.keystore)
            KeyStore keystore = Methods.loadKeyStore("test.keystore", "keystore");
            System.out.println(Methods.getPublicKeyE4(keystore, "test", "keystore"));
        }

        // Ejercicio 1.5 -------------------------------------------------------------------------//
        private static void Ejercicio1_5() {
            KeyPair keyPair = Methods.randomGenerate(1024);
            byte[] sign = Methods.signData("hola".getBytes(), keyPair.getPrivate());
            System.out.println(new String(sign));
        }

        // Ejercicio 1.6 -------------------------------------------------------------------------//
        private static void Ejercicio1_6() {
            KeyPair keyPair = Methods.randomGenerate(1024);
            byte[] text = "hola".getBytes();
            byte[] sign = Methods.signData(text, keyPair.getPrivate());
            boolean validated = Methods.validateSignature(text, sign, keyPair.getPublic());
            System.out.println(validated);
        }

        // Ejercicio 2.1 -------------------------------------------------------------------------//
        private static void Ejercicio2_1(){
            System.out.println("Dades Xifrades");
            System.out.println("byte[][] encWrappedData = new byte[2][];");

            System.out.println("Generacio de Clau");
            System.out.println("KeyGenerator kgen = KeyGenerator.getInstance(\"AES\");\n" + "kgen.init(128);");

            System.out.println("Algortimo de Cifrado");
            System.out.println("Cipher cipher = Cipher.getInstance(\"AES\");\n" + "cipher.init(Cipher.ENCRYPT_MODE, sKey);");

            System.out.println("Dades Cifradas");
            System.out.println("byte[] encMsg = cipher.doFinal(data);");

            System.out.println("Algortimo de 'Wrapping'");
            System.out.println("cipher = Cipher.getInstance(\"RSA/ECB/PKCS1Padding\");\n" + "cipher.init(Cipher.WRAP_MODE, pub);");

            System.out.println("Llave Cifrada");
            System.out.println("byte[] encKey = cipher.wrap(sKey);");

            System.out.println("Datos Cifrados 'Wrapped'");
            System.out.println("encWrappedData[0] = encMsg;\n" + "encWrappedData[1] = encKey;");
        }
        // Ejercicio 2.2 -------------------------------------------------------------------------//
        private static void Ejercicio2_2(){
            KeyPair keyPair = Methods.randomGenerate(1024);
            byte[] text = "texto".getBytes();

            byte[][] encryptWrapped = Methods.encryptWrappedData(text, keyPair.getPublic());
            byte[] decryptWrapped = Methods.decryptWrappedData(encryptWrapped, keyPair.getPrivate());

            System.out.println(new String(decryptWrapped));
        }
}

class Methods {

    //Ejercicio 1.1 & 1.2 (No me acuerdo exactamente que metodos eran)
    public static KeyPair randomGenerate(int len) {
        KeyPair keys = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(len);
            keys = keyGen.genKeyPair();
        } catch (Exception ex) {
            System.err.println("Generador no disponible.");
        }
        return keys;
    }

    public static KeyStore loadKeyStore(String ksFile, String ksPwd) throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        File f = new File (ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream (f);
            ks.load(in, ksPwd.toCharArray());
        }
        return ks;
    }

    public static byte[] encryptData(byte[] data, PublicKey pub) {
        byte[] encryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            encryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptData(byte[] data, PrivateKey Priv) {
        byte[] decryptedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, Priv);
            decryptedData =  cipher.doFinal(data);
        } catch (Exception  ex) {
            System.err.println("Error xifrant: " + ex);
        }
        return decryptedData;
    }

    public static SecretKey keygenKeyGeneration(int keySize) {
        SecretKey sKey = null;
        if ((keySize == 128)||(keySize == 192)||(keySize == 256)) {
            try {
                KeyGenerator kgen = KeyGenerator.getInstance("AES");
                kgen.init(keySize);
                sKey = kgen.generateKey();

            } catch (NoSuchAlgorithmException ex) {
                System.err.println("Generador no disponible.");
            }
        }
        return sKey;
    }

    // Ejercicio1.3
    public static PublicKey getPublicKeyEj3(File file) throws CertificateException, FileNotFoundException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(new FileInputStream(file));
        return certificate.getPublicKey();
    }

    //Ejercicio1.4
    public static PublicKey getPublicKeyE4(KeyStore ks, String alias, String pwMyKey) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        Key key;
        PublicKey publicKey = null;
        key = ks.getKey(alias, pwMyKey.toCharArray());
        if (key instanceof PrivateKey){
            Certificate cert = ks.getCertificate(alias);
            publicKey = cert.getPublicKey();
        }
        return publicKey;
    }

    //Ejercicio1.5
    public static byte[] signData(byte[] data, PrivateKey priv) {
        byte[] signature = null;

        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(priv);
            signer.update(data);
            signature = signer.sign();
        } catch (Exception ex) {
            System.err.println("Error signant les dades: " + ex);
        }
        return signature;
    }

    //Ejercicio1.6
    public static boolean validateSignature(byte[] data, byte[] signature, PublicKey pub) {
        boolean isValid = false;
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(pub);
            signer.update(data);
            isValid = signer.verify(signature);
        } catch (Exception ex) {
            System.err.println("Error validant les dades: " + ex);
        }
        return isValid;
    }

    //Ejercicio2.1
    public static byte[][] encryptWrappedData(byte[] data, PublicKey pub) {
        byte[][] encWrappedData = new byte[2][];
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            SecretKey sKey = kgen.generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, sKey);
            byte[] encMsg = cipher.doFinal(data);
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.WRAP_MODE, pub);
            byte[] encKey = cipher.wrap(sKey);
            encWrappedData[0] = encMsg;
            encWrappedData[1] = encKey;
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return encWrappedData;
    }

    //Ejercicio2.2
    public static byte[] decryptWrappedData(byte[][] data, PrivateKey privateKey) {
        byte[][] decWrappedData = new byte[2][];
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.UNWRAP_MODE, privateKey);
            Key decKey = cipher.unwrap(data[1], "AES", Cipher.PRIVATE_KEY);

            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, decKey);
            byte[] decMsg = cipher.doFinal(data[0]);
            decWrappedData[0] = decMsg;
        } catch (Exception  ex) {
            System.err.println("Ha succeït un error xifrant: " + ex);
        }
        return decWrappedData[0];
    }
}
