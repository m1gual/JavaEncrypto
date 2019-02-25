package general;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
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

        if (keyType == KeyType.PUBLIC_KEY) {
            PublicKey publicKey = (PublicKey) in.readObject();
            in.close();
            return publicKey;
        }
        if (keyType == KeyType.PRIVATE_KEY) {
            PrivateKey privateKey = (PrivateKey) in.readObject();
            in.close();
            return privateKey;
        }
        if (keyType == KeyType.AES_KEY) {
            SecretKey aesKey = (SecretKey) in.readObject();
            in.close();
            return aesKey;
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

        if (keyType == KeyType.PUBLIC_KEY) {
            return readSerializedKey(binaryKey, keyType);
        }
        if (keyType == KeyType.PRIVATE_KEY) {
            return readSerializedKey(binaryKey, keyType);
        }
        if (keyType == KeyType.AES_KEY) {
            return readSerializedKey(binaryKey, keyType);
        }

        return null;
    }
}
