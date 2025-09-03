package cn.labzen.algorithm.crypto;

import cn.labzen.algorithm.crypto.checksum.Algorithms;
import cn.labzen.tool.definition.Constants;
import cn.labzen.tool.util.Bytes;
import net.jacksum.algorithms.AbstractChecksum;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import static net.jacksum.HashFunctionFactory.getHashFunction;

/**
 * 校验和算法 <a href="https://en.wikipedia.org/wiki/Checksum">Checksum</a>
 * <p>
 * 提供[Algorithms]中的算法，具体实现采用<a href="https://jacksum.net">jacksum</a>
 */
public final class Checksums {

  public static final Map<Algorithms, AbstractChecksum> CHECKSUM_INSTANCES;

  static {
    try {
      CHECKSUM_INSTANCES = new HashMap<>();
      CHECKSUM_INSTANCES.put(Algorithms.ADLER32, getHashFunction("adler32"));
      CHECKSUM_INSTANCES.put(Algorithms.CKSUM, getHashFunction("cksum"));
      CHECKSUM_INSTANCES.put(Algorithms.CRC8, getHashFunction("crc8"));
      CHECKSUM_INSTANCES.put(Algorithms.CRC16, getHashFunction("crc16"));
      CHECKSUM_INSTANCES.put(Algorithms.CRC32, getHashFunction("crc32"));
      CHECKSUM_INSTANCES.put(Algorithms.CRC32_MPEG2, getHashFunction("crc32_mpeg2"));
      CHECKSUM_INSTANCES.put(Algorithms.CRC64, getHashFunction("crc64"));
      CHECKSUM_INSTANCES.put(Algorithms.CRC64_ECMA, getHashFunction("crc64_ecma"));
      CHECKSUM_INSTANCES.put(Algorithms.ELF, getHashFunction("elf"));
      CHECKSUM_INSTANCES.put(Algorithms.FCS16, getHashFunction("fcs16"));
      CHECKSUM_INSTANCES.put(Algorithms.FLETCHER16, getHashFunction("fletcher16"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV0_64, getHashFunction("fnv-0_64"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV0_128, getHashFunction("fnv-0_128"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV0_256, getHashFunction("fnv-0_256"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV0_512, getHashFunction("fnv-0_512"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV0_1024, getHashFunction("fnv-0_1024"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV1_64, getHashFunction("fnv-1_64"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV1_128, getHashFunction("fnv-1_128"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV1_256, getHashFunction("fnv-1_256"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV1_512, getHashFunction("fnv-1_512"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV1_1024, getHashFunction("fnv-1_1024"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV1A_64, getHashFunction("fnv-1a_64"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV1A_128, getHashFunction("fnv-1a_128"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV1A_256, getHashFunction("fnv-1a_256"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV1A_512, getHashFunction("fnv-1a_512"));
      CHECKSUM_INSTANCES.put(Algorithms.FNV1A_1024, getHashFunction("fnv-1a_1024"));
      CHECKSUM_INSTANCES.put(Algorithms.JOAAT32, getHashFunction("joaat"));
      CHECKSUM_INSTANCES.put(Algorithms.SUM32, getHashFunction("sum32"));
      CHECKSUM_INSTANCES.put(Algorithms.SUM48, getHashFunction("sum48"));
      CHECKSUM_INSTANCES.put(Algorithms.SUM56, getHashFunction("sum56"));
      CHECKSUM_INSTANCES.put(Algorithms.SUMBSD, getHashFunction("sum_bsd"));
      CHECKSUM_INSTANCES.put(Algorithms.XOR8, getHashFunction("xor8"));
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  private Checksums() {
  }

  /**
   * 对字节数组做校验和算法
   *
   * @param bytes 需要做校验的字节数组
   */
  public static Long bytes(byte[] bytes, Algorithms algorithm) {
    AbstractChecksum checksum = CHECKSUM_INSTANCES.get(algorithm);
    if (checksum == null) {
      return null;
    }

    checksum.update(bytes);
    long value = checksum.getValue();
    checksum.reset();
    return value;
  }

  /**
   * 对字符串做校验和算法，默认字符串是UTF-8编码
   *
   * @param plaintext 需要做校验的字节数组
   */
  public static Long string(String plaintext, Algorithms algorithm) {
    return string(plaintext, Constants.DEFAULT_CHARSET, algorithm);
  }

  /**
   * 对字符串做校验和算法
   *
   * @param plaintext 需要做校验的字节数组
   * @param charset   字符串的编码格式
   */
  public static Long string(String plaintext, Charset charset, Algorithms algorithm) {
    return bytes(plaintext.getBytes(charset), algorithm);
  }

  /**
   * 对文件做校验和算法
   *
   * @param file 需要做校验的文件
   */
  public static Long file(File file, Algorithms algorithm) {
    if (file == null || !file.exists() || !file.isFile()) {
      return null;
    }

    try {
      return bytes(Files.readAllBytes(file.toPath()), algorithm);
    } catch (IOException e) {
      return null;
    }
  }

  /**
   * 对字符串做校验和算法
   *
   * @param obj 需要做校验的字节数组
   */
  public static Long any(Object obj, Algorithms algorithm) {
    return bytes(Bytes.objectToBytes(obj), algorithm);
  }

}
