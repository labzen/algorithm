@file:Suppress("unused", "SpellCheckingInspection")

package cn.labzen.algorithm.crypto

import cn.labzen.tool.definition.Constants
import cn.labzen.tool.exception.FileException
import cn.labzen.tool.kotlin.throwRuntimeUnless
import cn.labzen.tool.util.Bytes
import org.bouncycastle.crypto.digests.Blake3Digest
import org.bouncycastle.jcajce.provider.digest.*
import org.bouncycastle.util.encoders.Hex
import java.io.File
import java.nio.charset.Charset
import java.nio.file.Files

/**
 * 加密散列函数 [Cryptographic hash function](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
 *
 * 提供下列各种算法：
 * - [Blake3](https://github.com/BLAKE3-team/BLAKE3)
 * - [Blake2](https://www.blake2.net)
 * - [Keccak](https://keccak.team/index.html)
 * - [Ripemd](https://homes.esat.kuleuven.be/~bosselae/ripemd160.html)
 * - [SM3](https://en.wikipedia.org/wiki/SM3_(hash_function))
 * - [Tiger](https://www.cs.technion.ac.il/~biham/Reports/Tiger/)
 * - [Whirlpool](https://web.archive.org/web/20171129084214/http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html)
 * - [MD5](www.w3.org/TR/1998/REC-DSig-label/MD5-1_0)
 * - [SHA-2](https://en.wikipedia.org/wiki/SHA-2)
 * - [SHA-3](https://en.wikipedia.org/wiki/SHA-3)
 */
object Digests {

  private val blake3DigestInstance = Blake3Digest()

  private val blake2b160DigestInstance = Blake2b.Blake2b160()
  private val blake2b256DigestInstance = Blake2b.Blake2b256()
  private val blake2b384DigestInstance = Blake2b.Blake2b384()
  private val blake2b512DigestInstance = Blake2b.Blake2b512()
  private val blake2s128DigestInstance = Blake2s.Blake2s128()
  private val blake2s160DigestInstance = Blake2s.Blake2s160()
  private val blake2s224DigestInstance = Blake2s.Blake2s224()
  private val blake2s256DigestInstance = Blake2s.Blake2s256()

  private val keccak224DigestInstance = Keccak.Digest224()
  private val keccak256DigestInstance = Keccak.Digest256()
  private val keccak288DigestInstance = Keccak.Digest288()
  private val keccak384DigestInstance = Keccak.Digest384()
  private val keccak512DigestInstance = Keccak.Digest512()

  private val ripemd128DigestInstance = RIPEMD128.Digest()
  private val ripemd160DigestInstance = RIPEMD160.Digest()
  private val ripemd256DigestInstance = RIPEMD256.Digest()
  private val ripemd320DigestInstance = RIPEMD320.Digest()

  private val sm3DigestInstance = SM3.Digest()
  private val tigerDigestInstance = Tiger.Digest()
  private val whirlpoolDigestInstance = Whirlpool.Digest()
  private val md5DigestInstance = MD5.Digest()

  private val sha2224DigestInstance = SHA224.Digest()
  private val sha2256DigestInstance = SHA256.Digest()
  private val sha2384DigestInstance = SHA384.Digest()
  private val sha2512DigestInstance = SHA512.Digest()
  private val sha3224DigestInstance = SHA3.Digest224()
  private val sha3256DigestInstance = SHA3.Digest256()
  private val sha3384DigestInstance = SHA3.Digest384()
  private val sha3512DigestInstance = SHA3.Digest512()

  /**
   * Blake3散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun blake3(bytes: ByteArray, cycles: Int = 1): String {
    blake3DigestInstance.update(bytes, 0, bytes.size)
    val digested = ByteArray(blake3DigestInstance.digestSize)
    blake3DigestInstance.doOutput(digested, 0, digested.size)
    blake3DigestInstance.reset()

    val hex = Hex.toHexString(digested)

    return if (cycles > 1) {
      blake3(hex, cycles - 1)
    } else hex
  }

  /**
   * Blake3散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param charset 字符串的编码格式（默认使用UTF-8）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun blake3(plaintext: String, charset: Charset = Constants.DEFAULT_CHARSET, cycles: Int = 1): String =
    blake3(plaintext.toByteArray(charset), cycles)

  /**
   * Blake3散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun blake3(plaintext: String, cycles: Int): String =
    blake3(plaintext, Constants.DEFAULT_CHARSET, cycles)

  /**
   * Blake3散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun blake3(obj: Any, cycles: Int = 1): String =
    blake3(Bytes.objectToBytes(obj), cycles)

  /**
   * Blake3散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  @Throws(FileException::class)
  fun blake3(file: File, cycles: Int = 1): String {
    file.exists().throwRuntimeUnless { FileException("MD5 - 文件不存在：${file.absolutePath}") }
    file.isFile.throwRuntimeUnless { FileException("MD5 - 路径不是一个文件：${file.absolutePath}") }

    return blake3(Files.readAllBytes(file.toPath()), cycles)
  }

  // ===================================================================================================================

  /**
   * Blake2散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param length Blake2算法长度（默认为BLAKE2B_256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun blake2(bytes: ByteArray, length: BlakeLength = BlakeLength.BLAKE2B_256, cycles: Int = 1): String {
    val digest = when (length) {
      BlakeLength.BLAKE2B_160 -> blake2b160DigestInstance
      BlakeLength.BLAKE2B_256 -> blake2b256DigestInstance
      BlakeLength.BLAKE2B_384 -> blake2b384DigestInstance
      BlakeLength.BLAKE2B_512 -> blake2b512DigestInstance
      BlakeLength.BLAKE2S_128 -> blake2s128DigestInstance
      BlakeLength.BLAKE2S_160 -> blake2s160DigestInstance
      BlakeLength.BLAKE2S_224 -> blake2s224DigestInstance
      BlakeLength.BLAKE2S_256 -> blake2s256DigestInstance
    }

    digest.update(bytes)
    val digested = digest.digest()
    digest.reset()

    val hex = Hex.toHexString(digested)

    return if (cycles > 1) {
      blake2(hex, length, cycles - 1)
    } else hex
  }

  /**
   * Blake2散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun blake2(bytes: ByteArray, cycles: Int): String =
    blake2(bytes, BlakeLength.BLAKE2B_256, cycles)

  /**
   * Blake2散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param charset
   * @param length Blake2算法长度（默认为BLAKE2B_256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun blake2(
    plaintext: String,
    charset: Charset = Constants.DEFAULT_CHARSET,
    length: BlakeLength = BlakeLength.BLAKE2B_256,
    cycles: Int = 1
  ): String =
    blake2(plaintext.toByteArray(charset), length, cycles)

  /**
   * Blake2散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun blake2(plaintext: String, cycles: Int): String =
    blake2(plaintext, Constants.DEFAULT_CHARSET, BlakeLength.BLAKE2B_256, cycles)

  /**
   * Blake2散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param length Blake2算法长度
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun blake2(plaintext: String, length: BlakeLength, cycles: Int): String =
    blake2(plaintext, Constants.DEFAULT_CHARSET, length, cycles)

  /**
   * Blake2散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param length Blake2算法长度（默认为BLAKE2B_256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun blake2(obj: Any, length: BlakeLength = BlakeLength.BLAKE2B_256, cycles: Int = 1): String =
    blake2(Bytes.objectToBytes(obj), length, cycles)

  /**
   * Blake2散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun blake2(obj: Any, cycles: Int): String =
    blake2(obj, BlakeLength.BLAKE2B_256, cycles)

  /**
   * Blake2散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param length Blake2算法长度（默认为BLAKE2B_256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  @Throws(FileException::class)
  fun blake2(file: File, length: BlakeLength = BlakeLength.BLAKE2B_256, cycles: Int = 1): String {
    file.exists().throwRuntimeUnless { FileException("MD5 - 文件不存在：${file.absolutePath}") }
    file.isFile.throwRuntimeUnless { FileException("MD5 - 路径不是一个文件：${file.absolutePath}") }

    return blake2(Files.readAllBytes(file.toPath()), length, cycles)
  }

  /**
   * Blake2散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @Synchronized
  @Throws(FileException::class)
  fun blake2(file: File, cycles: Int): String =
    blake2(file, BlakeLength.BLAKE2B_256, cycles)

  enum class BlakeLength {
    BLAKE2B_160, BLAKE2B_256, BLAKE2B_384, BLAKE2B_512, BLAKE2S_128, BLAKE2S_160, BLAKE2S_224, BLAKE2S_256
  }

  // ===================================================================================================================

  /**
   * Keccak散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param length Keccak算法长度（默认为KECCAK_256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun keccak(bytes: ByteArray, length: KeccakLength = KeccakLength.KECCAK_256, cycles: Int = 1): String {
    val digest: Keccak.DigestKeccak = when (length) {
      KeccakLength.KECCAK_224 -> keccak224DigestInstance
      KeccakLength.KECCAK_256 -> keccak256DigestInstance
      KeccakLength.KECCAK_288 -> keccak288DigestInstance
      KeccakLength.KECCAK_384 -> keccak384DigestInstance
      KeccakLength.KECCAK_512 -> keccak512DigestInstance
    }

    digest.update(bytes)
    val digested = digest.digest()
    digest.reset()

    val hex = Hex.toHexString(digested)

    return if (cycles > 1) {
      keccak(hex, length, cycles - 1)
    } else hex
  }

  /**
   * Keccak散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun keccak(bytes: ByteArray, cycles: Int): String =
    keccak(bytes, KeccakLength.KECCAK_256, cycles)

  /**
   * Keccak散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param charset
   * @param length Keccak算法长度（默认为KECCAK_256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun keccak(
    plaintext: String,
    charset: Charset = Constants.DEFAULT_CHARSET,
    length: KeccakLength = KeccakLength.KECCAK_256,
    cycles: Int = 1
  ): String =
    keccak(plaintext.toByteArray(charset), length, cycles)

  /**
   * Keccak散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun keccak(plaintext: String, cycles: Int): String =
    keccak(plaintext, Constants.DEFAULT_CHARSET, KeccakLength.KECCAK_256, cycles)

  /**
   * Keccak散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param length Keccak算法长度
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun keccak(plaintext: String, length: KeccakLength, cycles: Int): String =
    keccak(plaintext, Constants.DEFAULT_CHARSET, length, cycles)

  /**
   * Keccak散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param length Keccak算法长度（默认为KECCAK_256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun keccak(obj: Any, length: KeccakLength = KeccakLength.KECCAK_256, cycles: Int = 1): String =
    keccak(Bytes.objectToBytes(obj), length, cycles)

  /**
   * Keccak散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun keccak(obj: Any, cycles: Int): String =
    keccak(obj, KeccakLength.KECCAK_256, cycles)

  /**
   * Keccak散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param length Keccak算法长度（默认为KECCAK_256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  @Throws(FileException::class)
  fun keccak(file: File, length: KeccakLength = KeccakLength.KECCAK_256, cycles: Int = 1): String {
    file.exists().throwRuntimeUnless { FileException("MD5 - 文件不存在：${file.absolutePath}") }
    file.isFile.throwRuntimeUnless { FileException("MD5 - 路径不是一个文件：${file.absolutePath}") }

    return keccak(Files.readAllBytes(file.toPath()), length, cycles)
  }

  /**
   * Keccak散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @Synchronized
  @Throws(FileException::class)
  fun keccak(file: File, cycles: Int): String =
    keccak(file, KeccakLength.KECCAK_256, cycles)

  enum class KeccakLength {
    KECCAK_224, KECCAK_256, KECCAK_288, KECCAK_384, KECCAK_512
  }

  // ===================================================================================================================

  /**
   * Ripemd散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param length Ripemd算法长度（默认为RIPEMD_160）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun ripemd(bytes: ByteArray, length: RipemdLength = RipemdLength.RIPEMD_160, cycles: Int = 1): String {
    val digest = when (length) {
      RipemdLength.RIPEMD_128 -> ripemd128DigestInstance
      RipemdLength.RIPEMD_160 -> ripemd160DigestInstance
      RipemdLength.RIPEMD_256 -> ripemd256DigestInstance
      RipemdLength.RIPEMD_320 -> ripemd320DigestInstance
    }

    digest.update(bytes)
    val digested = digest.digest()
    digest.reset()

    val hex = Hex.toHexString(digested)

    return if (cycles > 1) {
      ripemd(hex, length, cycles - 1)
    } else hex
  }

  /**
   * Ripemd散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun ripemd(bytes: ByteArray, cycles: Int): String =
    ripemd(bytes, RipemdLength.RIPEMD_160, cycles)

  /**
   * Ripemd散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param charset
   * @param length Ripemd算法长度（默认为RIPEMD_160）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun ripemd(
    plaintext: String,
    charset: Charset = Constants.DEFAULT_CHARSET,
    length: RipemdLength = RipemdLength.RIPEMD_160,
    cycles: Int = 1
  ): String =
    ripemd(plaintext.toByteArray(charset), length, cycles)

  /**
   * Ripemd散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun ripemd(plaintext: String, cycles: Int): String =
    ripemd(plaintext, Constants.DEFAULT_CHARSET, RipemdLength.RIPEMD_160, cycles)

  /**
   * Ripemd散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param length Keccak算法长度
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun ripemd(plaintext: String, length: RipemdLength, cycles: Int): String =
    ripemd(plaintext, Constants.DEFAULT_CHARSET, length, cycles)

  /**
   * Ripemd散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param length Ripemd算法长度（默认为RIPEMD_160）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun ripemd(obj: Any, length: RipemdLength = RipemdLength.RIPEMD_160, cycles: Int = 1): String =
    ripemd(Bytes.objectToBytes(obj), length, cycles)

  /**
   * Ripemd散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun ripemd(obj: Any, cycles: Int): String =
    ripemd(obj, RipemdLength.RIPEMD_160, cycles)

  /**
   * Ripemd散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param length Ripemd算法长度（默认为RIPEMD_160）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  @Throws(FileException::class)
  fun ripemd(file: File, length: RipemdLength = RipemdLength.RIPEMD_160, cycles: Int = 1): String {
    file.exists().throwRuntimeUnless { FileException("MD5 - 文件不存在：${file.absolutePath}") }
    file.isFile.throwRuntimeUnless { FileException("MD5 - 路径不是一个文件：${file.absolutePath}") }

    return ripemd(Files.readAllBytes(file.toPath()), length, cycles)
  }

  /**
   * Ripemd散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @Synchronized
  @Throws(FileException::class)
  fun ripemd(file: File, cycles: Int): String =
    ripemd(file, RipemdLength.RIPEMD_160, cycles)

  enum class RipemdLength {
    RIPEMD_128, RIPEMD_160, RIPEMD_256, RIPEMD_320
  }

  // ===================================================================================================================

  /**
   * 国密SM3散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun sm3(bytes: ByteArray, cycles: Int = 1): String {
    sm3DigestInstance.update(bytes)
    val digested = sm3DigestInstance.digest()
    sm3DigestInstance.reset()

    val hex = Hex.toHexString(digested)

    return if (cycles > 1) {
      sm3(hex, cycles - 1)
    } else hex
  }

  /**
   * 国密SM3散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param charset 字符串的编码格式（默认使用UTF-8）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun sm3(plaintext: String, charset: Charset = Constants.DEFAULT_CHARSET, cycles: Int = 1): String =
    sm3(plaintext.toByteArray(charset), cycles)

  /**
   * 国密SM3散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun sm3(plaintext: String, cycles: Int): String =
    sm3(plaintext, Constants.DEFAULT_CHARSET, cycles)

  /**
   * 国密SM3散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun sm3(obj: Any, cycles: Int = 1): String =
    sm3(Bytes.objectToBytes(obj), cycles)

  /**
   * 国密SM3散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  @Throws(FileException::class)
  fun sm3(file: File, cycles: Int = 1): String {
    file.exists().throwRuntimeUnless { FileException("MD5 - 文件不存在：${file.absolutePath}") }
    file.isFile.throwRuntimeUnless { FileException("MD5 - 路径不是一个文件：${file.absolutePath}") }

    return sm3(Files.readAllBytes(file.toPath()), cycles)
  }

  // ===================================================================================================================

  /**
   * Tiger散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun tiger(bytes: ByteArray, cycles: Int = 1): String {
    tigerDigestInstance.update(bytes)
    val digested = tigerDigestInstance.digest()
    tigerDigestInstance.reset()

    val hex = Hex.toHexString(digested)

    return if (cycles > 1) {
      tiger(hex, cycles - 1)
    } else hex
  }

  /**
   * Tiger散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param charset 字符串的编码格式（默认使用UTF-8）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun tiger(plaintext: String, charset: Charset = Constants.DEFAULT_CHARSET, cycles: Int = 1): String =
    tiger(plaintext.toByteArray(charset), cycles)

  /**
   * Tiger散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun tiger(plaintext: String, cycles: Int): String =
    tiger(plaintext, Constants.DEFAULT_CHARSET, cycles)

  /**
   * Tiger散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun tiger(obj: Any, cycles: Int = 1): String =
    tiger(Bytes.objectToBytes(obj), cycles)

  /**
   * Tiger散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  @Throws(FileException::class)
  fun tiger(file: File, cycles: Int = 1): String {
    file.exists().throwRuntimeUnless { FileException("MD5 - 文件不存在：${file.absolutePath}") }
    file.isFile.throwRuntimeUnless { FileException("MD5 - 路径不是一个文件：${file.absolutePath}") }

    return tiger(Files.readAllBytes(file.toPath()), cycles)
  }

  // ===================================================================================================================

  /**
   * Whirlpool散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun whirlpool(bytes: ByteArray, cycles: Int = 1): String {
    whirlpoolDigestInstance.update(bytes)
    val digested = whirlpoolDigestInstance.digest()
    whirlpoolDigestInstance.reset()

    val hex = Hex.toHexString(digested)

    return if (cycles > 1) {
      whirlpool(hex, cycles - 1)
    } else hex
  }

  /**
   * Whirlpool散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param charset 字符串的编码格式（默认使用UTF-8）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun whirlpool(plaintext: String, charset: Charset = Constants.DEFAULT_CHARSET, cycles: Int = 1): String =
    whirlpool(plaintext.toByteArray(charset), cycles)

  /**
   * Whirlpool散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun whirlpool(plaintext: String, cycles: Int): String =
    whirlpool(plaintext, Constants.DEFAULT_CHARSET, cycles)

  /**
   * Whirlpool散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun whirlpool(obj: Any, cycles: Int = 1): String =
    whirlpool(Bytes.objectToBytes(obj), cycles)

  /**
   * Whirlpool散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  @Throws(FileException::class)
  fun whirlpool(file: File, cycles: Int = 1): String {
    file.exists().throwRuntimeUnless { FileException("MD5 - 文件不存在：${file.absolutePath}") }
    file.isFile.throwRuntimeUnless { FileException("MD5 - 路径不是一个文件：${file.absolutePath}") }

    return whirlpool(Files.readAllBytes(file.toPath()), cycles)
  }

  // ===================================================================================================================

  /**
   * MD5散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun md5(bytes: ByteArray, cycles: Int = 1): String {
    md5DigestInstance.update(bytes)
    val digested = md5DigestInstance.digest()
    md5DigestInstance.reset()

    val hex = Hex.toHexString(digested)

    return if (cycles > 1) {
      md5(hex, cycles - 1)
    } else hex
  }

  /**
   * MD5散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param charset 字符串的编码格式（默认使用UTF-8）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun md5(plaintext: String, charset: Charset = Constants.DEFAULT_CHARSET, cycles: Int = 1): String =
    md5(plaintext.toByteArray(charset), cycles)

  /**
   * MD5散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun md5(plaintext: String, cycles: Int): String =
    md5(plaintext, Constants.DEFAULT_CHARSET, cycles)

  /**
   * MD5散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun md5(obj: Any, cycles: Int = 1): String =
    md5(Bytes.objectToBytes(obj), cycles)

  /**
   * MD5散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  @Throws(FileException::class)
  fun md5(file: File, cycles: Int = 1): String {
    file.exists().throwRuntimeUnless { FileException("MD5 - 文件不存在：${file.absolutePath}") }
    file.isFile.throwRuntimeUnless { FileException("MD5 - 路径不是一个文件：${file.absolutePath}") }

    return md5(Files.readAllBytes(file.toPath()), cycles)
  }

  // ===================================================================================================================

  /**
   * SHA-2散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param length SHA-2算法长度（默认为SHA-256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun sha2(bytes: ByteArray, length: SHALength = SHALength.SHA_256, cycles: Int = 1): String {
    val digest = when (length) {
      SHALength.SHA_224 -> sha2224DigestInstance
      SHALength.SHA_256 -> sha2256DigestInstance
      SHALength.SHA_384 -> sha2384DigestInstance
      SHALength.SHA_512 -> sha2512DigestInstance
    }

    digest.update(bytes)
    val digested = digest.digest()
    digest.reset()

    val hex = Hex.toHexString(digested)

    return if (cycles > 1) {
      sha2(hex, length, cycles - 1)
    } else hex
  }

  /**
   * SHA-2散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun sha2(bytes: ByteArray, cycles: Int): String =
    sha2(bytes, SHALength.SHA_256, cycles)

  /**
   * SHA-2散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param charset
   * @param length SHA-2算法长度（默认为SHA-256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun sha2(
    plaintext: String,
    charset: Charset = Constants.DEFAULT_CHARSET,
    length: SHALength = SHALength.SHA_256,
    cycles: Int = 1
  ): String =
    sha2(plaintext.toByteArray(charset), length, cycles)

  /**
   * SHA-2散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun sha2(plaintext: String, cycles: Int): String =
    sha2(plaintext, Constants.DEFAULT_CHARSET, SHALength.SHA_256, cycles)

  /**
   * SHA-2散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param length SHA-2算法长度
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun sha2(plaintext: String, length: SHALength, cycles: Int): String =
    sha2(plaintext, Constants.DEFAULT_CHARSET, length, cycles)

  /**
   * SHA-2散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param length SHA-2算法长度（默认为SHA-256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun sha2(obj: Any, length: SHALength = SHALength.SHA_256, cycles: Int = 1): String =
    sha2(Bytes.objectToBytes(obj), length, cycles)

  /**
   * SHA-2散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun sha2(obj: Any, cycles: Int): String =
    sha2(obj, SHALength.SHA_256, cycles)

  /**
   * SHA-2散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param length SHA-2算法长度（默认为SHA-256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  @Throws(FileException::class)
  fun sha2(file: File, length: SHALength = SHALength.SHA_256, cycles: Int = 1): String {
    file.exists().throwRuntimeUnless { FileException("MD5 - 文件不存在：${file.absolutePath}") }
    file.isFile.throwRuntimeUnless { FileException("MD5 - 路径不是一个文件：${file.absolutePath}") }

    return sha2(Files.readAllBytes(file.toPath()), length, cycles)
  }

  /**
   * SHA-2散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @Synchronized
  @Throws(FileException::class)
  fun sha2(file: File, cycles: Int): String =
    sha2(file, SHALength.SHA_256, cycles)

  // ===================================================================================================================

  /**
   * SHA-3散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param length SHA-3算法长度（默认为SHA-256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun sha3(bytes: ByteArray, length: SHALength = SHALength.SHA_256, cycles: Int = 1): String {
    val digest: SHA3.DigestSHA3 = when (length) {
      SHALength.SHA_224 -> sha3224DigestInstance
      SHALength.SHA_256 -> sha3256DigestInstance
      SHALength.SHA_384 -> sha3384DigestInstance
      SHALength.SHA_512 -> sha3512DigestInstance
    }

    digest.update(bytes)
    val digested = digest.digest()
    digest.reset()

    val hex = Hex.toHexString(digested)

    return if (cycles > 1) {
      sha3(hex, length, cycles - 1)
    } else hex
  }

  /**
   * SHA-3散列摘要算法
   *
   * @param bytes 需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun sha3(bytes: ByteArray, cycles: Int): String =
    sha3(bytes, SHALength.SHA_256, cycles)

  /**
   * SHA-3散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param charset
   * @param length SHA-3算法长度（默认为SHA-256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun sha3(
    plaintext: String,
    charset: Charset = Constants.DEFAULT_CHARSET,
    length: SHALength = SHALength.SHA_256,
    cycles: Int = 1
  ): String =
    sha3(plaintext.toByteArray(charset), length, cycles)

  /**
   * SHA-3散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun sha3(plaintext: String, cycles: Int): String =
    sha3(plaintext, Constants.DEFAULT_CHARSET, SHALength.SHA_256, cycles)

  /**
   * SHA-3散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param length SHA-3算法长度
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun sha3(plaintext: String, length: SHALength, cycles: Int): String =
    sha3(plaintext, Constants.DEFAULT_CHARSET, length, cycles)

  /**
   * SHA-3散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param length SHA-3算法长度（默认为SHA-256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  fun sha3(obj: Any, length: SHALength = SHALength.SHA_256, cycles: Int = 1): String =
    sha3(Bytes.objectToBytes(obj), length, cycles)

  /**
   * SHA-3散列摘要算法
   *
   * @param obj 需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   */
  @JvmStatic
  @Synchronized
  fun sha3(obj: Any, cycles: Int): String =
    sha3(obj, SHALength.SHA_256, cycles)

  /**
   * SHA-3散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param length SHA-3算法长度（默认为SHA-256）
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @JvmOverloads
  @Synchronized
  @Throws(FileException::class)
  fun sha3(file: File, length: SHALength = SHALength.SHA_256, cycles: Int = 1): String {
    file.exists().throwRuntimeUnless { FileException("MD5 - 文件不存在：${file.absolutePath}") }
    file.isFile.throwRuntimeUnless { FileException("MD5 - 路径不是一个文件：${file.absolutePath}") }

    return sha3(Files.readAllBytes(file.toPath()), length, cycles)
  }

  /**
   * SHA-3散列摘要算法
   *
   * @param file 需要做摘要的文件
   * @param cycles 散列摘要次数（默认1）
   */
  @JvmStatic
  @Synchronized
  @Throws(FileException::class)
  fun sha3(file: File, cycles: Int): String =
    sha3(file, SHALength.SHA_256, cycles)

  // ===================================================================================================================

  enum class SHALength {
    SHA_224, SHA_256, SHA_384, SHA_512
  }
}
