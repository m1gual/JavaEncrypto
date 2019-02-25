package general;

import java.io.IOException;

public interface IKeyManager {
    byte[] serializeKey(Object key) throws IOException;

    Object readSerializedKey(byte[] binaryKey, KeyType keyType) throws ClassNotFoundException, IOException;

    String encodeKey(Object key) throws IOException;

    Object readEncodedKey(String textKey, KeyType keyType) throws IOException, ClassNotFoundException;


}
