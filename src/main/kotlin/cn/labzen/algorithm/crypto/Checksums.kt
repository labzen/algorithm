package cn.labzen.algorithm.crypto

import cn.labzen.tool.definition.Constants
import cn.labzen.tool.exception.FileException
import cn.labzen.tool.kotlin.throwRuntimeUnless
import cn.labzen.tool.util.Bytes
import net.jacksum.HashFunctionFactory.getHashFunction
import java.io.File
import java.nio.charset.Charset
import java.nio.file.Files

/**
 * 校验和算法 [Checksum](https://en.wikipedia.org/wiki/Checksum)
 *
 * 提供[Algorithms]中的算法，具体实现采用[jacksum](https://jacksum.net)
 */
object Checksums {

  private val checksumInstances = mapOf(
    Pair(Algorithms.ADLER32, getHashFunction("adler32")),
    Pair(Algorithms.CKSUM, getHashFunction("cksum")),
    Pair(Algorithms.CRC8, getHashFunction("crc8")),
    Pair(Algorithms.CRC16, getHashFunction("crc16")),
    Pair(Algorithms.CRC32, getHashFunction("crc32")),
    Pair(Algorithms.CRC32_MPEG2, getHashFunction("crc32_mpeg2")),
    Pair(Algorithms.CRC64, getHashFunction("crc64")),
    Pair(Algorithms.CRC64_ECMA, getHashFunction("crc64_ecma")),
    Pair(Algorithms.ELF, getHashFunction("elf")),
    Pair(Algorithms.FCS16, getHashFunction("fcs16")),
    Pair(Algorithms.FLETCHER16, getHashFunction("fletcher16")),
    Pair(Algorithms.FNV0_64, getHashFunction("fnv-0_64")),
    Pair(Algorithms.FNV0_128, getHashFunction("fnv-0_128")),
    Pair(Algorithms.FNV0_256, getHashFunction("fnv-0_256")),
    Pair(Algorithms.FNV0_512, getHashFunction("fnv-0_512")),
    Pair(Algorithms.FNV0_1024, getHashFunction("fnv-0_1024")),
    Pair(Algorithms.FNV1_64, getHashFunction("fnv-1_64")),
    Pair(Algorithms.FNV1_128, getHashFunction("fnv-1_128")),
    Pair(Algorithms.FNV1_256, getHashFunction("fnv-1_256")),
    Pair(Algorithms.FNV1_512, getHashFunction("fnv-1_512")),
    Pair(Algorithms.FNV1_1024, getHashFunction("fnv-1_1024")),
    Pair(Algorithms.FNV1A_64, getHashFunction("fnv-1a_64")),
    Pair(Algorithms.FNV1A_128, getHashFunction("fnv-1a_128")),
    Pair(Algorithms.FNV1A_256, getHashFunction("fnv-1a_256")),
    Pair(Algorithms.FNV1A_512, getHashFunction("fnv-1a_512")),
    Pair(Algorithms.FNV1A_1024, getHashFunction("fnv-1a_1024")),
    Pair(Algorithms.JOAAT32, getHashFunction("joaat")),
    Pair(Algorithms.SUM32, getHashFunction("sum32")),
    Pair(Algorithms.SUM48, getHashFunction("sum48")),
    Pair(Algorithms.SUM56, getHashFunction("sum56")),
    Pair(Algorithms.SUMBSD, getHashFunction("sum_bsd")),
    Pair(Algorithms.XOR8, getHashFunction("xor8"))
  )

  /**
   * 对字节数组做校验和算法
   *
   * @param bytes 需要做校验的字节数组
   */
  @JvmStatic
  @Synchronized
  fun bytes(bytes: ByteArray, algorithms: Algorithms): Long =
    checksumInstances[algorithms].let {
      it!!.update(bytes)
      val value = it.value
      it.reset()
      value
    }

  /**
   * 对字符串做校验和算法
   *
   * @param plaintext 需要做校验的字节数组
   * @param charset 字符串的编码格式（默认使用UTF-8）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun string(plaintext: String, charset: Charset = Constants.DEFAULT_CHARSET, algorithms: Algorithms): Long =
    bytes(plaintext.toByteArray(charset), algorithms)

  /**
   * 对文件做校验和算法
   *
   * @param file 需要做校验的文件
   */
  @JvmStatic
  @Synchronized
  @Throws(FileException::class)
  fun file(file: File, algorithms: Algorithms): Long {
    file.exists().throwRuntimeUnless { FileException("MD5 - 文件不存在：${file.absolutePath}") }
    file.isFile.throwRuntimeUnless { FileException("MD5 - 路径不是一个文件：${file.absolutePath}") }

    return bytes(Files.readAllBytes(file.toPath()), algorithms)
  }

  /**
   * 对任何对象实例（Serializable）做校验和算法
   *
   * @param obj 需要做校验的任意类实例
   */
  @JvmStatic
  @Synchronized
  fun any(obj: Any, algorithms: Algorithms): Long =
    bytes(Bytes.objectToBytes(obj), algorithms)

  /**
   * 校验和算法
   */
  enum class Algorithms {
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
     * http://www.burtleburtle.net/bob/hash/doobs.html
     */
    JOAAT32,
    SUM32,
    SUM48,
    SUM56,
    SUMBSD,
    XOR8
  }
}
