package cn.labzen.algorithm.crypto.checksum;

/**
 * 校验和算法
 */
public enum Algorithms {

  /**
   * [Adler-32](https://en.wikipedia.org/wiki/Adler-32) checksum
   */
  ADLER32,

  /**
   * Cksum: GNU C source (POSIX 1003.2 checksum)
   */
  CKSUM,

  /**
   * [Cyclic redundancy check](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) checksum
   */
  CRC8,

  /**
   * [Cyclic redundancy check](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) checksum
   */
  CRC16,

  /**
   * [Cyclic redundancy check](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) checksum
   */
  CRC32,

  /**
   * [Cyclic redundancy check](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) checksum
   */
  CRC32_MPEG2,

  /**
   * [Cyclic redundancy check](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) checksum
   */
  CRC64,

  /**
   * [Cyclic redundancy check](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) checksum
   */
  CRC64_ECMA,
  ELF,
  FCS16,

  /**
   * [Fletcher](https://en.wikipedia.org/wiki/Fletcher%27s_checksum) checksum
   */
  FLETCHER16,
  FNV0_64,
  FNV0_128,
  FNV0_256,
  FNV0_512,
  FNV0_1024,
  FNV1_64,
  FNV1_128,
  FNV1_256,
  FNV1_512,
  FNV1_1024,
  FNV1A_64,
  FNV1A_128,
  FNV1A_256,
  FNV1A_512,
  FNV1A_1024,

  /**
   * Jenkins's One-at-a-Time Hash (joaat) See also
   * <a href="http://www.burtleburtle.net/bob/hash/doobs.html">http://www.burtleburtle.net/bob/hash/doobs.html</a>
   */
  JOAAT32,
  SUM32,
  SUM48,
  SUM56,
  SUMBSD,
  XOR8
}
