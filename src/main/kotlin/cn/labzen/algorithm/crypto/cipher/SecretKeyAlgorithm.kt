package cn.labzen.algorithm.crypto.cipher

/**
 * The following algorithm names can be specified when requesting an instance of SecretKeyFactory.
 *
 * 以下算法名称可以在请求SecretKeyFactory实例时指定。
 */
@Deprecated("", ReplaceWith("", ""))
enum class SecretKeyAlgorithm(val value: String) {

  /**
   * Constructs secret keys for use with the AES algorithm.
   */
  AES("AES"),

  /**
   * Constructs secret keys for use with the ARCFOUR algorithm.
   */
  ARC_FOUR("ARCFOUR"),

  /**
   * Constructs secrets keys for use with the DES algorithm.
   */
  DES("DES"),

  /**
   * Constructs secrets keys for use with the DESede (Triple-DES) algorithm.
   */
  DESEDE("DESede"),

  /**
   * Secret-key factory for use with PKCS5 password-based encryption, where <digest> is a message digest,
   * <prf> is a pseudo-random function, and <encryption> is an encryption algorithm. Examples:
   *
   * PBEWithMD5AndDES (PKCS #5, 1.5),
   * PBEWithHmacSHA256AndAES_128 (PKCS #5, 2.0)
   *
   * Note: These all use only the low order 8 bits of each password character.
   */
  PBE_WITH_MD5_AND_DES("PBEWithMD5AndDES"),

  /**
   * Secret-key factory for use with PKCS5 password-based encryption, where <digest> is a message digest,
   * <prf> is a pseudo-random function, and <encryption> is an encryption algorithm. Examples:
   *
   * PBEWithMD5AndDES (PKCS #5, 1.5),
   * PBEWithHmacSHA256AndAES_128 (PKCS #5, 2.0)
   *
   * Note: These all use only the low order 8 bits of each password character.
   */
  PBE_WITH_HMAC_SHA256_AND_AES_128("PBEWithHmacSHA256AndAES_128"),

  /**
   * Password-based key-derivation algorithm found in PKCS #5 2.0 using the specified pseudo-random function (<prf>). Example:
   *
   * PBKDF2WithHmacSHA256.
   */
  PBKDF2_WITH_HMAC_SHA256("PBKDF2WithHmacSHA256")
}
