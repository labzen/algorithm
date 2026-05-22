package cn.labzen.algorithm.crypto.cipher;

import cn.labzen.tool.util.Bytes;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.HashMap;
import java.util.Map;

public class SymmetricalCipher {

  private static final KeyGeneratorAlgorithm DEFAULT_KEY_GENERATOR_ALGORITHM = KeyGeneratorAlgorithm.AES;
  private static final CipherAlgorithm DEFAULT_CIPHER_ALGORITHM = CipherAlgorithm.AES;
  private static final Map<String, KeyGenerator> KEY_GENERATORS = new HashMap<>();

  private final CipherTransformation transformation;

  private Key key;
  private AlgorithmParameters parameters;
  private Cipher encryptCipher;
  private Cipher decryptCipher;

  public SymmetricalCipher(CipherTransformation transformation, Key key, AlgorithmParameters parameters) {
    this.transformation = transformation;
    this.key = key;
    this.parameters = parameters;
  }

  public SymmetricalCipher(CipherTransformation transformation) {
    this(transformation, null, null);
  }

  public SymmetricalCipher withKey(Key key) {
    return new SymmetricalCipher(this.transformation, key, this.parameters);
  }

  public SymmetricalCipher withKey(String stringKey, CipherAlgorithm algorithm) {
    return withKey(stringKey.getBytes(), algorithm);
  }

  public SymmetricalCipher withKey(byte[] byteKey, CipherAlgorithm algorithm) {
    return new SymmetricalCipher(this.transformation,
        new SecretKeySpec(byteKey, algorithm == null ? DEFAULT_CIPHER_ALGORITHM.getValue() : algorithm.getValue()),
        this.parameters);
  }

  public SymmetricalCipher randomKey(KeyGeneratorAlgorithm algorithm) {
    int size;
    switch (algorithm) {
      case AES -> size = 128;
      case DES -> size = 56;
      case DESEDE -> size = 168;
      default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
    }
    return randomKey(algorithm, size);
  }

  public SymmetricalCipher randomKey(KeyGeneratorAlgorithm algorithm, int size) {
    String mapKey = algorithm.getValue() + "_" + size;
    KeyGenerator keyGenerator = KEY_GENERATORS.computeIfAbsent(mapKey, mk -> {
      try {
        KeyGenerator instance = KeyGenerator.getInstance(algorithm.getValue());
        instance.init(size);
        return instance;
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      }
    });

    SecretKey key = keyGenerator.generateKey();
    return withKey(key);
  }

  public String stringKey() {
    return Bytes.bytesToHexString(key.getEncoded());
  }

  public byte[] byteKey() {
    if (key != null) {
      return key.getEncoded();
    }
    return null;
  }

  public SymmetricalCipher withParameter(AlgorithmParameterSpec parameter) {
    try {
      AlgorithmParameters instance = AlgorithmParameters.getInstance(transformation.algorithm().getValue());
      instance.init(parameter);
      return new SymmetricalCipher(this.transformation, this.key, instance);
    } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
      throw new RuntimeException(e);
    }
  }

  public SymmetricalCipher withIVParameter(byte[] bytes) {
    return withParameter(new IvParameterSpec(bytes));
  }

  public byte[] encrypt(String plaintext) {
    return encrypt(plaintext.getBytes());
  }

  public byte[] encrypt(byte[] bytes) {
    if (encryptCipher == null) {
      encryptCipher = createCipherInstance(Cipher.ENCRYPT_MODE);
    }

    try {
      return encryptCipher.doFinal(bytes);
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new RuntimeException(e);
    }
  }

  public byte[] decrypt(byte[] ciphertext) {
    if (decryptCipher == null) {
      decryptCipher = createCipherInstance(Cipher.DECRYPT_MODE);
    }

    try {
      return decryptCipher.doFinal(ciphertext);
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new RuntimeException(e);
    }
  }

  private Cipher createCipherInstance(int mode) {
    try {
      Cipher instance = Cipher.getInstance(transformation.toString());
      if (parameters != null) {
        instance.init(mode, key, parameters);
      } else {
        instance.init(mode, key);
      }
      return instance;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
             InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }
}
