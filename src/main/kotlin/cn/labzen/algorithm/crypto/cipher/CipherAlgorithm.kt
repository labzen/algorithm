package cn.labzen.algorithm.crypto.cipher

/**
 * The following names can be specified as the algorithm component in a transformation when requesting an instance of Cipher.
 *
 * 当请求Cipher实例时，可以将下列名称指定为转换中的算法组件。
 */
enum class CipherAlgorithm(val value: String) {

  /**
   * Advanced Encryption Standard as specified by NIST in FIPS 197. Also known as the Rijndael algorithm by Joan Daemen and Vincent Rijmen,
   * AES is a 128-bit block cipher supporting keys of 128, 192, and 256 bits.
   *
   * To use the AES cipher with only one valid key size, use the format AES_<n>, where <n> can be 128, 192 or 256.
   */
  AES("AES"),

  /**
   * The AES key wrapping algorithm as described in RFC 3394.
   *
   * To use the AESWrap cipher with only one valid key size, use the format AESWrap_<n>, where <n> can be 128, 192, or 256.
   */
  AES_WRAP("AESWrap"),

  /**
   * A stream cipher believed to be fully interoperable with the RC4 cipher developed by Ron Rivest.
   * For more information, see K. Kaukonen and R. Thayer, "A Stream Cipher Encryption Algorithm 'Arcfour'", Internet Draft (expired).
   */
  ARC_FOUR("ARCFOUR"),

  /**
   * The Blowfish block cipher designed by Bruce Schneier.
   */
  BLOWFISH("Blowfish"),

  /**
   * The Digital Encryption Standard as described in FIPS PUB 46-3.
   */
  DES("DES"),

  /**
   * Triple DES Encryption (also known as DES-EDE, 3DES, or Triple-DES). Data is encrypted using the DES algorithm three separate times.
   * It is first encrypted using the first subkey, then decrypted with the second subkey, and encrypted with the third subkey.
   */
  DESEDE("DESede"),

  /**
   * The DESede key wrapping algorithm as described in RFC 3217.
   */
  DESEDE_WRAP("DESedeWrap"),

  /**
   * Elliptic Curve Integrated Encryption Scheme
   */
  ECIES("ECIES"),

  /**
   * The password-based encryption algorithm defined in PKCS #5, using the specified message digest (<digest>) or pseudo-random
   * function (<prf>) and encryption algorithm (<encryption>). Examples:
   *
   * PBEWithMD5AndDES: The password-based encryption algorithm as defined in RSA Laboratories, "PKCS #5: Password-Based
   * Encryption Standard," version 1.5, Nov 1993. Note that this algorithm implies CBC as the cipher mode and PKCS5Padding
   * as the padding scheme and cannot be used with any other cipher modes or padding schemes.
   */
  PBE_WITH_MD5_AND_DES("PBEWithMD5AndDES"),

  /**
   * The password-based encryption algorithm defined in PKCS #5, using the specified message digest (<digest>) or pseudo-random
   * function (<prf>) and encryption algorithm (<encryption>). Examples:
   *
   * PBEWithHmacSHA256AndAES_128: The password-based encryption algorithm as defined in RSA Laboratories, "PKCS #5:
   * Password-Based Cryptography Standard," version 2.0, September 2000.
   */
  PBE_WITH_HMAC_SHA256_AND_AES_128("PBEWithHmacSHA256AndAES_128"),

  /**
   * Variable-key-size encryption algorithms developed by Ron Rivest for RSA Data Security, Inc.
   */
  RC2("RC2"),

  /**
   * Variable-key-size encryption algorithms developed by Ron Rivest for RSA Data Security, Inc. (See note prior for ARCFOUR.)
   */
  RC4("RC4"),

  /**
   * Variable-key-size encryption algorithms developed by Ron Rivest for RSA Data Security, Inc.
   */
  RC5("RC5"),

  /**
   * The RSA encryption algorithm as defined in PKCS #1
   */
  RSA("RSA")
}
