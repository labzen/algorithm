package cn.labzen.algorithm.crypto.cipher

/**
 * The following algorithm names can be specified when requesting an instance of KeyGenerator.
 *
 * 以下算法名称可以在请求KeyGenerator实例时指定。
 */
enum class KeyGeneratorAlgorithm(val value: String) {

  /**
   * Key generator for use with the AES algorithm.
   */
  AES("AES"),

  /**
   * Key generator for use with the ARCFOUR (RC4) algorithm.
   */
  RC4("ARCFOUR"),

  /**
   * Key generator for use with the Blowfish algorithm.
   */
  BLOWFISH("Blowfish"),

  /**
   * Key generator for use with the DES algorithm.
   */
  DES("DES"),

  /**
   * Key generator for use with the DESede (triple-DES) algorithm.
   */
  DESEDE("DESede"),

  /**
   * Key generator for use with the HmacMD5 algorithm.
   */
  HMAC_MD5("HmacMD5"),

  /**
   * Keys generator for use with the various flavors of the HmacSHA algorithms.
   */
  HMAC_SHA1("HmacSHA1"),

  /**
   * Keys generator for use with the various flavors of the HmacSHA algorithms.
   */
  HMAC_SHA224("HmacSHA224"),

  /**
   * Keys generator for use with the various flavors of the HmacSHA algorithms.
   */
  HMAC_SHA256("HmacSHA256"),

  /**
   * Keys generator for use with the various flavors of the HmacSHA algorithms.
   */
  HMAC_SHA384("HmacSHA384"),

  /**
   * Keys generator for use with the various flavors of the HmacSHA algorithms.
   */
  HMAC_SHA512("HmacSHA512"),

  /**
   * Key generator for use with the RC2 algorithm.
   */
  RC2("RC2")
}
