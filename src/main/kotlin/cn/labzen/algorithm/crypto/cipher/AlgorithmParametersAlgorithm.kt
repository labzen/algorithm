package cn.labzen.algorithm.crypto.cipher

/**
 * The algorithm names in this section can be specified when generating an instance of AlgorithmParameters.
 *
 * 在生成AlgorithmParameters实例时，可以指定本节中的算法名称。
 */
enum class AlgorithmParametersAlgorithm(val value: String) {

  /**
   * Parameters for use with the AES algorithm.
   */
  AES("AES"),

  /**
   * Parameters for use with the Blowfish algorithm.
   */
  BLOWFISH("Blowfish"),

  /**
   * Parameters for use with the DES algorithm.
   */
  DES("DES"),

  /**
   * Parameters for use with the DESede algorithm.
   */
  DESEDE("DESede"),

  /**
   * Parameters for use with the DiffieHellman algorithm.
   */
  DIFFIE_HELLMAN("DiffieHellman"),

  /**
   * Parameters for use with the Digital Signature Algorithm.
   */
  DSA("DSA"),

  /**
   * Parameters for use with the EC algorithm.
   */
  EC("EC"),

  /**
   * Parameters for use with the OAEP algorithm.
   */
  OAEP("OAEP"),

  /**
   * Parameters for use with the PBEWith<digest>And<encryption> algorithm. Examples: PBEWithMD5AndDES, and PBEWithHmacSHA256AndAES.
   */
  PBE_WITH_MD5_AND_DES("PBEWithMD5AndDES"),

  /**
   * Parameters for use with the PBEWith<digest>And<encryption> algorithm. Examples: PBEWithMD5AndDES, and PBEWithHmacSHA256AndAES.
   */
  PBE_WITH_HMAC_SHA256_AND_AES("PBEWithHmacSHA256AndAES"),

  /**
   * Parameters for use with the PBE algorithm. This name should not be used, in preference to the more specific
   * PBE-algorithm names previously listed.
   */
  PBE("PBE"),

  /**
   * Parameters for use with the RC2 algorithm.
   */
  RC2("RC2")
}
