package cn.labzen.algorithm.crypto;

import cn.labzen.algorithm.crypto.cipher.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public final class Ciphers {

  private static final BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();
  private static final CipherTransformation DEFAULT_SYMMETRICAL_TRANSFORMATION = new CipherTransformation(
      CipherAlgorithm.AES,
      CipherMode.CBC,
      CipherPadding.PKCS5_PADDING);

  static {
    Security.addProvider(BC_PROVIDER);
  }

  private Ciphers() {
  }

  public static SymmetricalCipher symmetrical() {
    return new SymmetricalCipher(DEFAULT_SYMMETRICAL_TRANSFORMATION);
  }

  public static SymmetricalCipher symmetrical(CipherTransformation transformation) {
    return new SymmetricalCipher(transformation);
  }

  public static SymmetricalCipher symmetrical(CipherAlgorithm algorithm, CipherMode mode, CipherPadding padding) {
    return new SymmetricalCipher(new CipherTransformation(algorithm, mode, padding));
  }

}
