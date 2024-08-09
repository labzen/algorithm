package cn.labzen.algorithm.crypto.cipher

/**
 * The following names can be specified as the padding component in a transformation when requesting an instance of Cipher.
 *
 * 当请求Cipher实例时，可以将下列名称指定为转换中的填充组件。
 */
enum class CipherPadding(val value: String) {
  /**
   * No padding.
   */
  NO_PADDING("NoPadding"),

  /**
   * This padding for block ciphers is described in 5.2 Block Encryption Algorithms in the W3C "XML Encryption Syntax and Processing" document.
   */
  ISO10126_PADDING("ISO10126Padding"),

  /**
   * Optimal Asymmetric Encryption. Padding scheme defined in PKCS1, where <digest> should be replaced by the message
   * digest and <mgf> by the mask generation function. Examples: OAEPWithMD5AndMGF1Padding and OAEPWithSHA-512AndMGF1Padding.
   *
   * If OAEPPadding is used, Cipher objects are initialized with a javax.crypto.spec.OAEPParameterSpec object to supply
   * values needed for OAEPPadding.
   */
  OAEP_PADDING("OAEPPadding"),

  /**
   * Optimal Asymmetric Encryption. Padding scheme defined in PKCS1, where <digest> should be replaced by the message
   * digest and <mgf> by the mask generation function. Examples: OAEPWithMD5AndMGF1Padding and OAEPWithSHA-512AndMGF1Padding.
   *
   * If OAEPPadding is used, Cipher objects are initialized with a javax.crypto.spec.OAEPParameterSpec object to supply
   * values needed for OAEPPadding.
   */
  OAEP_WITH_MD5_AND_MGF1_PADDING("OAEPWithMD5AndMGF1Padding"),

  /**
   * Optimal Asymmetric Encryption. Padding scheme defined in PKCS1, where <digest> should be replaced by the message
   * digest and <mgf> by the mask generation function. Examples: OAEPWithMD5AndMGF1Padding and OAEPWithSHA-512AndMGF1Padding.
   *
   * If OAEPPadding is used, Cipher objects are initialized with a javax.crypto.spec.OAEPParameterSpec object to supply
   * values needed for OAEPPadding.
   */
  OAEP_WITH_SHA512_AND_MGF1_PADDING("OAEPWithSHA-512AndMGF1Padding"),

  /**
   * The padding scheme described in PKCS#1, used with the RSA algorithm.
   */
  PKCS1_PADDING("PKCS1Padding"),

  /**
   * The padding scheme described in RSA Laboratories, "PKCS #5: Password-Based Encryption Standard, version 1.5, November 1993".
   */
  PKCS5_PADDING("PKCS5Padding"),
  PKCS7_PADDING("PKCS7Padding"),

  /**
   * The padding scheme defined in the SSL Protocol Version 3.0, November 18, 1996, section 5.2.3.2 (CBC block cipher):
   *
   * ```
   * block-ciphered struct {
   * opaque content[SSLCompressed.length];
   * opaque MAC[CipherSpec.hash_size];
   * uint8 padding[GenericBlockCipher.padding_length];
   * uint8 padding_length;
   * } GenericBlockCipher;
   * ```
   *
   * The size of an instance of a GenericBlockCipher must be a multiple of the block cipher's block length. The padding
   * length, which is always present, contributes to the padding, which implies that if:
   *
   * > sizeof(content) + sizeof(MAC) % block_length = 0,
   *
   * padding has to be (block_length - 1) bytes long, because of the existence of padding_length.
   *
   * This makes the padding scheme similar (but not quite) to PKCS5Padding, where the padding length is encoded in the
   * padding (and ranges from 1 to block_length). With the SSL scheme, the sizeof(padding) is encoded in the always present padding_length and therefore ranges from 0 to block_length-1.
   */
  SSL3_PADDING("SSL3Padding")
}
