package me.vkku;

import java.io.*;
import java.security.*;
import java.util.Objects;

public class GenSig
{

        public static void main(String[] args) {

            if (args.length > 1) {
                System.out.println("Usage: GenSig nameOfFileToSign");
            }
            else {
                generateSignAndPublicKey();
            }
        }

    private static void generateSignAndPublicKey() {

            try{

                KeyPair keyPair = generateKeyPair();

                //Signing - Check README for algorithm alternatives
                Signature dsa = generateSignature("SHA256withDSA", "SUN", keyPair.getPrivate());

                readFileAndUpdateSign("src/main/resources/data.txt", dsa);
                GenSig.class.getClassLoader().getResourceAsStream("data.txt");
                byte[] signature = dsa.sign();

                writeToFile("src/main/java/org/example/sign", signature);
                writeToFile("src/main/java/org/example/public-key", keyPair.getPublic().getEncoded());

            }catch (Exception e) {
                System.err.println("Caught exception " + e.toString());
            }

    }

    private static void readFileAndUpdateSign(String path, Signature dsa)
            throws IOException, SignatureException {
        FileInputStream fileInputStream = new FileInputStream(path);
        BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = bufferedInputStream.read(buffer)) > 0){
            dsa.update(buffer);
        }
        bufferedInputStream.close();
    }

    private static KeyPair generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        //Check README for algorithm alternatives
        SecureRandom random = SecureRandom.getInstanceStrong();
        keyGen.initialize(1024, random);
        return keyGen.generateKeyPair();
    }

    public static void writeToFile(String fileName, byte[] content) throws IOException {
            FileOutputStream fileOutputStream = new FileOutputStream(fileName);
            fileOutputStream.write(content);
            fileOutputStream.close();
        }

    public static Signature generateSignature(String algorithm, String provider, PrivateKey privateKey)
            throws InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException {
        Signature dsa = Signature.getInstance("SHA256withDSA", "SUN");
        dsa.initSign(privateKey);
        return dsa;
    }

}
