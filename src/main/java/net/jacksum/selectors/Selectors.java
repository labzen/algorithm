/*


  Jacksum 3.2.0 - a checksum utility in Java
  Copyright (c) 2001-2022 Dipl.-Inf. (FH) Johann N. Löfflmann,
  All Rights Reserved, <https://jacksum.net>.

  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
  details.

  You should have received a copy of the GNU General Public License along with
  this program. If not, see <https://www.gnu.org/licenses/>.


 */
package net.jacksum.selectors;

public class Selectors {

  public final static Class<?>[] allSupportedSelectorClasses = {Adler32_Selector.class,
                                                                CksumMinix_Selector.class,
                                                                Cksum_Selector.class,
                                                                CRC8_Selector.class,
                                                                CRC16_Selector.class,
                                                                CRC16Minix_Selector.class,
                                                                CRC24_Selector.class,
                                                                CRC32_Selector.class,
                                                                CRC32mpeg2_Selector.class,
                                                                CRC32bzip2_Selector.class,
                                                                CRC32fddi_Selector.class,
                                                                CRC32ubi_Selector.class,
                                                                CRC32_PHP_Selector.class,
                                                                CRC32c_Selector.class,
                                                                CRC64_Selector.class,
                                                                CRC64_ECMA182_Selector.class,
                                                                CRC64_GO_Selector.class,
                                                                CRC64xz_Selector.class,
                                                                Elf_Selector.class,
                                                                FCS16_Selector.class,
                                                                Fletcher16_Selector.class,
                                                                FNV0_Selector.class,
                                                                FNV1_Selector.class,
                                                                FNV1a_Selector.class,
                                                                Joaat32_Selector.class,
                                                                SumBSD_Selector.class,
                                                                SumMinix_Selector.class,
                                                                SumSysV_Selector.class,
                                                                Sum8_Selector.class,
                                                                Sum16_Selector.class,
                                                                Sum24_Selector.class,
                                                                Sum32_Selector.class,
                                                                Sum40_Selector.class,
                                                                Sum48_Selector.class,
                                                                Sum56_Selector.class,
                                                                Xor8_Selector.class};

  public final static Class<?>[] allSelectorClasses = {
      // the combined hash algorithm has to be the first in this list!
      CombinedChecksum_Selector.class,
      // most popular algorithms first due to performance reasons
      // order is also used by the brute forcer in order to find algorithms

      // cryptographic hash functions
      // ============================

      // Haraka v2 is a secure and efficient short-input (256 or 512 bits) hash function
      // means: the input size must be exactly 32 bytes for Haraka256 resp. 64 bytes for Haraka512
      // which makes it less attractive for Jacksum, because Jacksum supports only hash functions
      // that convert variable length input into fixed length hashes.
      // Haraka256_Selector.class,
      // Haraka512_Selector.class,

      // Non-cryptographic hash functions
      // ================================

      // Checksums
      // ---------
      Adler32_Selector.class,
      Cksum_Selector.class,
      SumBSD_Selector.class,
      SumSysV_Selector.class,
      Elf_Selector.class,
      FNV0_Selector.class,
      FNV1_Selector.class,
      FNV1a_Selector.class,
      Fletcher16_Selector.class,
      CksumMinix_Selector.class,
      SumMinix_Selector.class,
      Sum56_Selector.class,
      Sum48_Selector.class,
      Sum40_Selector.class,
      Sum32_Selector.class,
      Sum24_Selector.class,
      Sum16_Selector.class,
      Sum8_Selector.class,
      Xor8_Selector.class,
      Joaat32_Selector.class,

      // CRCs
      // ----
      CRCGeneric_Selector.class,

      CRC64_Selector.class,
      CRC64_ECMA182_Selector.class,
      CRC64_GO_Selector.class,
      CRC64xz_Selector.class,

      CRC32_Selector.class,
      CRC32_PHP_Selector.class,
      CRC32ubi_Selector.class,
      CRC32fddi_Selector.class,
      CRC32bzip2_Selector.class,
      CRC32mpeg2_Selector.class,
      CRC32c_Selector.class,

      CRC24_Selector.class,

      CRC16_Selector.class,
      CRC16Minix_Selector.class,
      FCS16_Selector.class,

      CRC8_Selector.class};
}
