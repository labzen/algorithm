package cn.labzen.algorithm.crypto;

import cn.labzen.algorithm.crypto.checksum.Algorithms;
import cn.labzen.tool.definition.Constants;
import cn.labzen.tool.util.Bytes;
import net.jacksum.algorithms.AbstractChecksum;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import static net.jacksum.HashFunctionFactory.getHashFunction;

/**
 * 校验和算法 <a href="https://en.wikipedia.org/wiki/Checksum">Checksum</a>
 * <p>
 * 提供[Algorithms]中的算法，具体实现采用<a href="https://jacksum.net">jacksum</a>
 */
public final class Checksums {

  private static final Map<Algorithms, String> CHECKSUM_ALGORITHM_NAMES;
  private static final int DEFAULT_BUFFER_SIZE = 8192;

  static {
    CHECKSUM_ALGORITHM_NAMES = Map.ofEntries(Map.entry(Algorithms.ADLER32, "adler32"),
        Map.entry(Algorithms.CKSUM, "cksum"),
        Map.entry(Algorithms.CRC8, "crc8"),
        Map.entry(Algorithms.CRC16, "crc16"),
        Map.entry(Algorithms.CRC32, "crc32"),
        Map.entry(Algorithms.CRC32_MPEG2, "crc32_mpeg2"),
        Map.entry(Algorithms.CRC64, "crc64"),
        Map.entry(Algorithms.CRC64_ECMA, "crc64_ecma"),
        Map.entry(Algorithms.ELF, "elf"),
        Map.entry(Algorithms.FCS16, "fcs16"),
        Map.entry(Algorithms.FLETCHER16, "fletcher16"),
        Map.entry(Algorithms.FNV0_64, "fnv-0_64"),
        Map.entry(Algorithms.FNV0_128, "fnv-0_128"),
        Map.entry(Algorithms.FNV0_256, "fnv-0_256"),
        Map.entry(Algorithms.FNV0_512, "fnv-0_512"),
        Map.entry(Algorithms.FNV0_1024, "fnv-0_1024"),
        Map.entry(Algorithms.FNV1_64, "fnv-1_64"),
        Map.entry(Algorithms.FNV1_128, "fnv-1_128"),
        Map.entry(Algorithms.FNV1_256, "fnv-1_256"),
        Map.entry(Algorithms.FNV1_512, "fnv-1_512"),
        Map.entry(Algorithms.FNV1_1024, "fnv-1_1024"),
        Map.entry(Algorithms.FNV1A_64, "fnv-1a_64"),
        Map.entry(Algorithms.FNV1A_128, "fnv-1a_128"),
        Map.entry(Algorithms.FNV1A_256, "fnv-1a_256"),
        Map.entry(Algorithms.FNV1A_512, "fnv-1a_512"),
        Map.entry(Algorithms.FNV1A_1024, "fnv-1a_1024"),
        Map.entry(Algorithms.JOAAT32, "joaat"),
        Map.entry(Algorithms.SUM32, "sum32"),
        Map.entry(Algorithms.SUM48, "sum48"),
        Map.entry(Algorithms.SUM56, "sum56"),
        Map.entry(Algorithms.SUMBSD, "sum_bsd"),
        Map.entry(Algorithms.XOR8, "xor8"));
  }

  private Checksums() {
  }

  /**
   * 对字节数组做校验和算法
   *
   * @param bytes 需要做校验的字节数组
   */
  public static Long bytes(byte[] bytes, Algorithms algorithm) {
    String algorithmName = CHECKSUM_ALGORITHM_NAMES.get(algorithm);
    if (algorithmName == null) {
      return null;
    }

    try {
      AbstractChecksum checksum = getHashFunction(algorithmName);
      checksum.update(bytes);
      return checksum.getValue();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Checksum algorithm not available: " + algorithmName, e);
    }
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

    String algorithmName = CHECKSUM_ALGORITHM_NAMES.get(algorithm);
    if (algorithmName == null) {
      return null;
    }

    try (InputStream in = Files.newInputStream(file.toPath())) {
      AbstractChecksum checksum = getHashFunction(algorithmName);
      byte[] buf = new byte[DEFAULT_BUFFER_SIZE];
      int read;
      while ((read = in.read(buf)) != -1) {
        checksum.update(buf, 0, read);
      }
      return checksum.getValue();
    } catch (IOException | NoSuchAlgorithmException e) {
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
