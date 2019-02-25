package general;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

public class KeyManager implements IKeyManager {

    @Override
    public byte[] serializeKey(Object key) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = new ObjectOutputStream(bos);
        out.writeObject(key);
        out.flush();

        byte[] binaryKey = bos.toByteArray();
        bos.close();

        return binaryKey;
    }

    @Override
    public Object readSerializedKey(byte[] binaryKey, KeyType keyType) throws ClassNotFoundException, IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(binaryKey);
        ObjectInput in = new ObjectInputStream(bis);

        switch (keyType) {
            case AES_KEY:
                SecretKey aesKey = (SecretKey) in.readObject();
                in.close();
                return aesKey;

            case PUBLIC_KEY:
                PublicKey publicKey = (PublicKey) in.readObject();
                in.close();
                return publicKey;

            case PRIVATE_KEY:
                PrivateKey privateKey = (PrivateKey) in.readObject();
                in.close();
                return privateKey;
        }

        return null;
    }

    @Override
    public String encodeKey(Object key) throws IOException {
        byte[] binaryKey = serializeKey(key);

        Encoder b64e = Base64.getEncoder();

        return b64e.encodeToString(binaryKey);
    }

    @Override
    public Object readEncodedKey(String textKey, KeyType keyType) throws IOException, ClassNotFoundException {
        Decoder b64e = Base64.getDecoder();
        byte[] binaryKey = b64e.decode(textKey);

        return readSerializedKey(binaryKey, keyType);
    }

    @Override
    public String getMDHash(String textKey, DigestAlgorithm digestAlgorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(getDigestAlgorithm(digestAlgorithm));
        md.update(textKey.getBytes());

        return toHex(md.digest());
    }

    private String getDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        switch (digestAlgorithm) {
            case MD5:
                return "MD5";
            case SHA_1:
                return "SHA-1";
            case SHA_256:
                return "SHA-256";
            case SHA_384:
                return "SHA-384";
            case SHA_512:
                return "SHA-512";
        }

        return null;
    }

    private String toHex(byte[] input) {
        StringBuilder hex = new StringBuilder();
        for (byte b : input) {
            String h = Integer.toHexString(b & 0xFF);
            if (h.length() == 1) {
                hex.append("0");
            }
            hex.append(h).append(" ");
        }

        return hex.toString().toUpperCase();
    }

}
