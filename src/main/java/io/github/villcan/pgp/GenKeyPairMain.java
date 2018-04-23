package io.github.villcan.pgp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

public class GenKeyPairMain {

    private static final String realName = "RealNameId";
    private static final String passphrase = "**********************";

    private static final String path = "/home/ubuntu/Temporal/PGPTempFolder";
    private static final boolean isArmored = true;
    private static final int keySize = 2048;

    public static void main(String[] args) throws IOException, PGPException, SignatureException, NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException {
        RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(keySize);
        KeyPair kp = kpg.generateKeyPair();

        String subPassphrase = passphrase.substring(0, 4);
        String publicKeyFileName = String.format("%s/%s-publicKey.asc", path, subPassphrase);
        String privateKeyFileName = String.format("%s/%s-privateKey.asc", path, subPassphrase);

        FileOutputStream out1 = new FileOutputStream(privateKeyFileName);
        FileOutputStream out2 = new FileOutputStream(publicKeyFileName);

        String realNameId = String.format("%s-%s", realName, subPassphrase);

        rkpg.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), realNameId, passphrase.toCharArray(), isArmored);
        System.out.println("PublicKey created: : " + publicKeyFileName);
        System.out.println("PrivateKey created: : " + privateKeyFileName);
    }
}
