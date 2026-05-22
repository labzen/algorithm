package cn.labzen.algorithm.crypto;

import cn.labzen.tool.exception.FileException;
import cn.labzen.tool.util.Bytes;
import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.jcajce.provider.digest.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import static java.lang.ThreadLocal.withInitial;

/**
 * 加密散列函数 <a href="https://en.wikipedia.org/wiki/Cryptographic_hash_function">Cryptographic hash function</a>
 * <p>
 * 提供下列各种算法：
 * <li> <a href="https://github.com/BLAKE3-team/BLAKE3">Blake3</a>
 * <li> <a href="https://www.blake2.net">Blake2</a>
 * <li> <a href="https://keccak.team/index.html">Keccak</a>
 * <li> <a href="https://homes.esat.kuleuven.be/~bosselae/ripemd160.html">Ripemd</a>
 * <li> <a href="https://en.wikipedia.org/wiki/SM3_(hash_function)">SM3</a>
 * <li> <a href="https://www.cs.technion.ac.il/~biham/Reports/Tiger/">Tiger</a>
 * <li> <a href="https://web.archive.org/web/20171129084214/http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html">Whirlpool</a>
 * <li> <a href="https://www.w3.org/TR/1998/REC-DSig-label/MD5-1_0">MD5</a>
 * <li> <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a>
 * <li> <a href="https://en.wikipedia.org/wiki/SHA-3">SHA-3</a>
 */
public final class Digests {

  private static final ThreadLocal<Blake3Digest> BLAKE3_DIGEST = withInitial(Blake3Digest::new);

  private static final ThreadLocal<BCMessageDigest> BLAKE2B_160_DIGEST = withInitial(Blake2b.Blake2b160::new);
  private static final ThreadLocal<BCMessageDigest> BLAKE2B_256_DIGEST = withInitial(Blake2b.Blake2b256::new);
  private static final ThreadLocal<BCMessageDigest> BLAKE2B_384_DIGEST = withInitial(Blake2b.Blake2b384::new);
  private static final ThreadLocal<BCMessageDigest> BLAKE2B_512_DIGEST = withInitial(Blake2b.Blake2b512::new);
  private static final ThreadLocal<BCMessageDigest> BLAKE2S_128_DIGEST = withInitial(Blake2s.Blake2s128::new);
  private static final ThreadLocal<BCMessageDigest> BLAKE2S_160_DIGEST = withInitial(Blake2s.Blake2s160::new);
  private static final ThreadLocal<BCMessageDigest> BLAKE2S_224_DIGEST = withInitial(Blake2s.Blake2s224::new);
  private static final ThreadLocal<BCMessageDigest> BLAKE2S_256_DIGEST = withInitial(Blake2s.Blake2s256::new);

  private static final ThreadLocal<Keccak.DigestKeccak> KECCAK224_DIGEST = withInitial(Keccak.Digest224::new);
  private static final ThreadLocal<Keccak.DigestKeccak> KECCAK256_DIGEST = withInitial(Keccak.Digest256::new);
  private static final ThreadLocal<Keccak.DigestKeccak> KECCAK288_DIGEST = withInitial(Keccak.Digest288::new);
  private static final ThreadLocal<Keccak.DigestKeccak> KECCAK384_DIGEST = withInitial(Keccak.Digest384::new);
  private static final ThreadLocal<Keccak.DigestKeccak> KECCAK512_DIGEST = withInitial(Keccak.Digest512::new);

  private static final ThreadLocal<BCMessageDigest> RIPEMD128_DIGEST = withInitial(RIPEMD128.Digest::new);
  private static final ThreadLocal<BCMessageDigest> RIPEMD160_DIGEST = withInitial(RIPEMD160.Digest::new);
  private static final ThreadLocal<BCMessageDigest> RIPEMD256_DIGEST = withInitial(RIPEMD256.Digest::new);
  private static final ThreadLocal<BCMessageDigest> RIPEMD320_DIGEST = withInitial(RIPEMD320.Digest::new);

  private static final ThreadLocal<BCMessageDigest> SM3_DIGEST = withInitial(SM3.Digest::new);
  private static final ThreadLocal<BCMessageDigest> TIGER_DIGEST = withInitial(Tiger.Digest::new);
  private static final ThreadLocal<BCMessageDigest> WHIRLPOOL_DIGEST = withInitial(Whirlpool.Digest::new);
  private static final ThreadLocal<BCMessageDigest> MD5_DIGEST = withInitial(MD5.Digest::new);

  private static final ThreadLocal<BCMessageDigest> SHA2_224_DIGEST = withInitial(SHA224.Digest::new);
  private static final ThreadLocal<BCMessageDigest> SHA2_256_DIGEST = withInitial(SHA256.Digest::new);
  private static final ThreadLocal<BCMessageDigest> SHA2_384_DIGEST = withInitial(SHA384.Digest::new);
  private static final ThreadLocal<BCMessageDigest> SHA2_512_DIGEST = withInitial(SHA512.Digest::new);
  private static final ThreadLocal<BCMessageDigest> SHA3_224_DIGEST = withInitial(SHA3.Digest224::new);
  private static final ThreadLocal<BCMessageDigest> SHA3_256_DIGEST = withInitial(SHA3.Digest256::new);
  private static final ThreadLocal<BCMessageDigest> SHA3_384_DIGEST = withInitial(SHA3.Digest384::new);
  private static final ThreadLocal<BCMessageDigest> SHA3_512_DIGEST = withInitial(SHA3.Digest512::new);

  private Digests() {
  }

  /**
   * Blake3散列摘要算法，默认字符编码UTF-8，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#blake3(String, Charset, int)
   */
  public static String blake3(String plaintext) {
    return blake3(plaintext, StandardCharsets.UTF_8, 1);
  }

  /**
   * Blake3散列摘要算法，默认字符编码UTF-8
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#blake3(String, Charset, int)
   */
  public static String blake3(String plaintext, int cycles) {
    return blake3(plaintext, StandardCharsets.UTF_8, cycles);
  }

  /**
   * Blake3散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param charset   字符编码
   * @param cycles    散列摘要次数
   */
  public static String blake3(String plaintext, Charset charset, int cycles) {
    return blake3(plaintext.getBytes(charset), cycles);
  }

  /**
   * Blake3散列摘要算法，默认摘要次数 1
   *
   * @param obj 需要做摘要的任意类实例
   * @see Digests#blake3(Object, int)
   */
  public static String blake3(Object obj) {
    return blake3(obj, 1);
  }

  /**
   * Blake3散列摘要算法
   *
   * @param obj    需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   */
  public static String blake3(Object obj, int cycles) {
    return blake3(Bytes.objectToBytes(obj), cycles);
  }

  /**
   * Blake3散列摘要算法，默认摘要次数 1
   *
   * @param file 需要做摘要的文件
   * @see Digests#blake3(File, int)
   */
  public static String blake3(File file) {
    return blake3(file, 1);
  }

  /**
   * Blake3散列摘要算法
   *
   * @param file   需要做摘要的文件
   * @param cycles 散列摘要次数
   */
  public static String blake3(File file, int cycles) throws FileException {
    if (file == null || !file.exists() || !file.isFile()) {
      throw new FileException("请确保文件正确: {}", file);
    }
    try {
      return blake3(Files.readAllBytes(file.toPath()), cycles);
    } catch (IOException e) {
      throw new FileException(e, "无法读取文件: {}", file);
    }
  }

  /**
   * Blake3散列摘要算法，默认摘要次数 1
   *
   * @param bytes 需要做摘要的字节数组
   * @see Digests#blake3(byte[], int)
   */
  public static String blake3(byte[] bytes) {
    return blake3(bytes, 1);
  }

  /**
   * Blake3散列摘要算法
   *
   * @param bytes  需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  public static String blake3(byte[] bytes, int cycles) {
    Blake3Digest digest = BLAKE3_DIGEST.get();
    digest.update(bytes, 0, bytes.length);
    int digestedSize = digest.getDigestSize();
    byte[] digested = new byte[digestedSize];
    digest.doOutput(digested, 0, digested.length);
    digest.reset();

    if (cycles == 1) {
      return Hex.toHexString(digested);
    }
    return blake3(digested, cycles - 1);
  }

  // ===================================================================================================================

  public enum Blake2Length {
    BLAKE2B_160, BLAKE2B_256, BLAKE2B_384, BLAKE2B_512, BLAKE2S_128, BLAKE2S_160, BLAKE2S_224, BLAKE2S_256
  }

  /**
   * Blake2散列摘要算法，默认编码UTF-8，默认算法长度为BLAKE2B_256，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#blake2(String, Blake2Length, int)
   */
  public static String blake2(String plaintext) {
    return blake2(plaintext, StandardCharsets.UTF_8, Blake2Length.BLAKE2B_256, 1);
  }

  /**
   * Blake2散列摘要算法，默认编码UTF-8，默认算法长度为BLAKE2B_256
   *
   * @param plaintext 需要做摘要的字符串
   * @param cycles    散列摘要次数
   * @see Digests#blake2(String, Blake2Length, int)
   */
  public static String blake2(String plaintext, int cycles) {
    return blake2(plaintext, StandardCharsets.UTF_8, Blake2Length.BLAKE2B_256, cycles);
  }

  /**
   * Blake2散列摘要算法，默认编码UTF-8，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @param length    Blake2算法长度
   * @see Digests#blake2(String, Blake2Length, int)
   */
  public static String blake2(String plaintext, Blake2Length length) {
    return blake2(plaintext, StandardCharsets.UTF_8, length, 1);
  }

  /**
   * Blake2散列摘要算法，默认编码UTF-8
   *
   * @param plaintext 需要做摘要的字符串
   * @param length    Blake2算法长度
   * @param cycles    散列摘要次数
   * @see Digests#blake2(String, Blake2Length, int)
   */
  public static String blake2(String plaintext, Blake2Length length, int cycles) {
    return blake2(plaintext, StandardCharsets.UTF_8, length, cycles);
  }

  /**
   * Blake2散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param charset   字符编码
   * @param length    Blake2算法长度
   * @param cycles    散列摘要次数
   * @see Digests#blake2(String, Blake2Length, int)
   */
  public static String blake2(String plaintext, Charset charset, Blake2Length length, int cycles) {
    return blake2(plaintext.getBytes(charset), length, cycles);
  }

  /**
   * Blake2散列摘要算法，默认算法长度为BLAKE2B_256，默认摘要次数 1
   *
   * @param obj 需要做摘要的任意类实例
   * @see Digests#blake2(Object, Blake2Length, int)
   */
  public static String blake2(Object obj) {
    return blake2(obj, Blake2Length.BLAKE2B_256, 1);
  }

  /**
   * Blake2散列摘要算法，默认算法长度为BLAKE2B_256
   *
   * @param obj    需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   * @see Digests#blake2(Object, Blake2Length, int)
   */
  public static String blake2(Object obj, int cycles) {
    return blake2(obj, Blake2Length.BLAKE2B_256, cycles);
  }

  /**
   * Blake2散列摘要算法，默认摘要次数 1
   *
   * @param obj    需要做摘要的任意类实例
   * @param length Blake2算法长度
   * @see Digests#blake2(Object, Blake2Length, int)
   */
  public static String blake2(Object obj, Blake2Length length) {
    return blake2(obj, length, 1);
  }

  /**
   * Blake2散列摘要算法
   *
   * @param obj    需要做摘要的任意类实例
   * @param length Blake2算法长度
   * @param cycles 散列摘要次数
   * @see Digests#blake2(Object, Blake2Length, int)
   */
  public static String blake2(Object obj, Blake2Length length, int cycles) {
    return blake2(Bytes.objectToBytes(obj), length, cycles);
  }

  /**
   * Blake2散列摘要算法，默认算法长度为BLAKE2B_256，默认摘要次数 1
   *
   * @param file 需要做摘要的文件
   * @see Digests#blake2(File, Blake2Length, int)
   */
  public static String blake2(File file) {
    return blake2(file, Blake2Length.BLAKE2B_256, 1);
  }

  /**
   * Blake2散列摘要算法，默认算法长度为BLAKE2B_256
   *
   * @param file   需要做摘要的文件
   * @param cycles 散列摘要次数
   * @see Digests#blake2(File, Blake2Length, int)
   */
  public static String blake2(File file, int cycles) {
    return blake2(file, Blake2Length.BLAKE2B_256, cycles);
  }

  /**
   * Blake2散列摘要算法，默认摘要次数 1
   *
   * @param file   需要做摘要的文件
   * @param length Blake2算法长度
   * @see Digests#blake2(File, Blake2Length, int)
   */
  public static String blake2(File file, Blake2Length length) {
    return blake2(file, length, 1);
  }

  /**
   * Blake2散列摘要算法
   *
   * @param file   需要做摘要的文件
   * @param length Blake2算法长度
   * @param cycles 散列摘要次数
   * @see Digests#blake2(File, Blake2Length, int)
   */
  public static String blake2(File file, Blake2Length length, int cycles) throws FileException {
    if (file == null || !file.exists() || !file.isFile()) {
      throw new FileException("请确保文件正确: {}", file);
    }
    try {
      return blake2(Files.readAllBytes(file.toPath()), length, cycles);
    } catch (IOException e) {
      throw new FileException(e, "无法读取文件: {}", file);
    }
  }

  /**
   * Blake2散列摘要算法，默认算法长度为BLAKE2B_256，默认摘要次数 1
   *
   * @param bytes 需要做摘要的字节数组
   * @see Digests#blake2(byte[], Blake2Length, int)
   */
  public static String blake2(byte[] bytes) {
    return blake2(bytes, Blake2Length.BLAKE2B_256, 1);
  }

  /**
   * Blake2散列摘要算法，默认算法长度为BLAKE2B_256
   *
   * @param bytes  需要做摘要的字节数组
   * @param cycles 散列摘要次数
   * @see Digests#blake2(byte[], Blake2Length, int)
   */
  public static String blake2(byte[] bytes, int cycles) {
    return blake2(bytes, Blake2Length.BLAKE2B_256, cycles);
  }

  /**
   * Blake2散列摘要算法，默认摘要次数 1
   *
   * @param bytes  需要做摘要的字节数组
   * @param length Blake2算法长度
   * @see Digests#blake2(byte[], Blake2Length, int)
   */
  public static String blake2(byte[] bytes, Blake2Length length) {
    return blake2(bytes, length, 1);
  }

  /**
   * Blake2散列摘要算法
   *
   * @param bytes  需要做摘要的字节数组
   * @param length Blake2算法长度
   * @param cycles 散列摘要次数
   */
  public static String blake2(byte[] bytes, Blake2Length length, int cycles) {
    BCMessageDigest digester;
    switch (length) {
      case BLAKE2B_160 -> digester = BLAKE2B_160_DIGEST.get();
      case BLAKE2B_256 -> digester = BLAKE2B_256_DIGEST.get();
      case BLAKE2B_384 -> digester = BLAKE2B_384_DIGEST.get();
      case BLAKE2B_512 -> digester = BLAKE2B_512_DIGEST.get();
      case BLAKE2S_128 -> digester = BLAKE2S_128_DIGEST.get();
      case BLAKE2S_160 -> digester = BLAKE2S_160_DIGEST.get();
      case BLAKE2S_224 -> digester = BLAKE2S_224_DIGEST.get();
      case BLAKE2S_256 -> digester = BLAKE2S_256_DIGEST.get();
      default -> throw new IllegalArgumentException("Unknown blake-length: " + length);
    }

    digester.update(bytes);
    byte[] digested = digester.digest();
    digester.reset();

    if (cycles == 1) {
      return Hex.toHexString(digested);
    }
    return blake2(digested, length, cycles - 1);
  }

  // ===================================================================================================================

  public enum KeccakLength {
    KECCAK_224, KECCAK_256, KECCAK_288, KECCAK_384, KECCAK_512
  }

  /**
   * Keccak散列摘要算法，默认编码UTF-8，默认算法长度为KECCAK_256，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#keccak(String, KeccakLength, int)
   */
  public static String keccak(String plaintext) {
    return keccak(plaintext, StandardCharsets.UTF_8, KeccakLength.KECCAK_256, 1);
  }

  /**
   * Keccak散列摘要算法，默认编码UTF-8，默认算法长度为KECCAK_256
   *
   * @param plaintext 需要做摘要的字符串
   * @param cycles    散列摘要次数
   * @see Digests#keccak(String, KeccakLength, int)
   */
  public static String keccak(String plaintext, int cycles) {
    return keccak(plaintext, StandardCharsets.UTF_8, KeccakLength.KECCAK_256, cycles);
  }

  /**
   * Keccak散列摘要算法，默认编码UTF-8，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @param length    Keccak算法长度
   * @see Digests#keccak(String, KeccakLength, int)
   */
  public static String keccak(String plaintext, KeccakLength length) {
    return keccak(plaintext, StandardCharsets.UTF_8, length, 1);
  }

  /**
   * Keccak散列摘要算法，默认编码UTF-8
   *
   * @param plaintext 需要做摘要的字符串
   * @param length    Keccak算法长度
   * @param cycles    散列摘要次数
   * @see Digests#keccak(String, KeccakLength, int)
   */
  public static String keccak(String plaintext, KeccakLength length, int cycles) {
    return keccak(plaintext, StandardCharsets.UTF_8, length, cycles);
  }

  /**
   * Keccak散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param charset   字符编码
   * @param length    Keccak算法长度
   * @param cycles    散列摘要次数
   * @see Digests#keccak(String, KeccakLength, int)
   */
  public static String keccak(String plaintext, Charset charset, KeccakLength length, int cycles) {
    return keccak(plaintext.getBytes(charset), length, cycles);
  }

  /**
   * Keccak散列摘要算法，默认算法长度为KECCAK_256，默认摘要次数 1
   *
   * @param obj 需要做摘要的任意类实例
   * @see Digests#keccak(Object, KeccakLength, int)
   */
  public static String keccak(Object obj) {
    return keccak(obj, KeccakLength.KECCAK_256, 1);
  }

  /**
   * Keccak散列摘要算法，默认算法长度为KECCAK_256
   *
   * @param obj    需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   * @see Digests#keccak(Object, KeccakLength, int)
   */
  public static String keccak(Object obj, int cycles) {
    return keccak(obj, KeccakLength.KECCAK_256, cycles);
  }

  /**
   * Keccak散列摘要算法，默认摘要次数 1
   *
   * @param obj    需要做摘要的任意类实例
   * @param length Keccak算法长度
   * @see Digests#keccak(Object, KeccakLength, int)
   */
  public static String keccak(Object obj, KeccakLength length) {
    return keccak(obj, length, 1);
  }

  /**
   * Keccak散列摘要算法
   *
   * @param obj    需要做摘要的任意类实例
   * @param length Keccak算法长度
   * @param cycles 散列摘要次数
   * @see Digests#keccak(Object, KeccakLength, int)
   */
  public static String keccak(Object obj, KeccakLength length, int cycles) {
    return keccak(Bytes.objectToBytes(obj), length, cycles);
  }

  /**
   * Keccak散列摘要算法，默认算法长度为KECCAK_256，默认摘要次数 1
   *
   * @param file 需要做摘要的文件
   * @see Digests#keccak(File, KeccakLength, int)
   */
  public static String keccak(File file) {
    return keccak(file, KeccakLength.KECCAK_256, 1);
  }

  /**
   * Keccak散列摘要算法，默认算法长度为KECCAK_256
   *
   * @param file   需要做摘要的文件
   * @param cycles 散列摘要次数
   * @see Digests#keccak(File, KeccakLength, int)
   */
  public static String keccak(File file, int cycles) {
    return keccak(file, KeccakLength.KECCAK_256, cycles);
  }

  /**
   * Keccak散列摘要算法，默认摘要次数 1
   *
   * @param file   需要做摘要的文件
   * @param length Keccak算法长度
   * @see Digests#keccak(File, KeccakLength, int)
   */
  public static String keccak(File file, KeccakLength length) {
    return keccak(file, length, 1);
  }

  /**
   * Keccak散列摘要算法
   *
   * @param file   需要做摘要的文件
   * @param length Keccak算法长度
   * @param cycles 散列摘要次数
   * @see Digests#keccak(File, KeccakLength, int)
   */
  public static String keccak(File file, KeccakLength length, int cycles) throws FileException {
    if (file == null || !file.exists() || !file.isFile()) {
      throw new FileException("请确保文件正确: {}", file);
    }
    try {
      return keccak(Files.readAllBytes(file.toPath()), length, cycles);
    } catch (IOException e) {
      throw new FileException(e, "无法读取文件: {}", file);
    }
  }

  /**
   * Keccak散列摘要算法，默认算法长度为KECCAK_256，默认摘要次数 1
   *
   * @param bytes 需要做摘要的字节数组
   * @see Digests#keccak(byte[], KeccakLength, int)
   */
  public static String keccak(byte[] bytes) {
    return keccak(bytes, KeccakLength.KECCAK_256, 1);
  }

  /**
   * Keccak散列摘要算法，默认算法长度为KECCAK_256
   *
   * @param bytes  需要做摘要的字节数组
   * @param cycles 散列摘要次数
   * @see Digests#keccak(byte[], KeccakLength, int)
   */
  public static String keccak(byte[] bytes, int cycles) {
    return keccak(bytes, KeccakLength.KECCAK_256, cycles);
  }

  /**
   * Keccak散列摘要算法，默认摘要次数 1
   *
   * @param bytes  需要做摘要的字节数组
   * @param length Keccak算法长度
   * @see Digests#keccak(byte[], KeccakLength, int)
   */
  public static String keccak(byte[] bytes, KeccakLength length) {
    return keccak(bytes, length, 1);
  }

  /**
   * Keccak散列摘要算法
   *
   * @param bytes  需要做摘要的字节数组
   * @param length Keccak算法长度
   * @param cycles 散列摘要次数
   */
  public static String keccak(byte[] bytes, KeccakLength length, int cycles) {
    Keccak.DigestKeccak digester;
    switch (length) {
      case KECCAK_224 -> digester = KECCAK224_DIGEST.get();
      case KECCAK_256 -> digester = KECCAK256_DIGEST.get();
      case KECCAK_288 -> digester = KECCAK288_DIGEST.get();
      case KECCAK_384 -> digester = KECCAK384_DIGEST.get();
      case KECCAK_512 -> digester = KECCAK512_DIGEST.get();
      default -> throw new IllegalArgumentException("Unknown keccak-length: " + length);
    }

    digester.update(bytes);
    byte[] digested = digester.digest();
    digester.reset();

    if (cycles == 1) {
      return Hex.toHexString(digested);
    }
    return keccak(digested, length, cycles - 1);
  }

  // ===================================================================================================================

  public enum RipemdLength {
    RIPEMD_128, RIPEMD_160, RIPEMD_256, RIPEMD_320
  }

  /**
   * Ripemd散列摘要算法，默认编码UTF-8，默认算法长度为RIPEMD_160，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#ripemd(String, RipemdLength, int)
   */
  public static String ripemd(String plaintext) {
    return ripemd(plaintext, StandardCharsets.UTF_8, RipemdLength.RIPEMD_160, 1);
  }

  /**
   * Ripemd散列摘要算法，默认编码UTF-8，默认算法长度为RIPEMD_160
   *
   * @param plaintext 需要做摘要的字符串
   * @param cycles    散列摘要次数
   * @see Digests#ripemd(String, RipemdLength, int)
   */
  public static String ripemd(String plaintext, int cycles) {
    return ripemd(plaintext, StandardCharsets.UTF_8, RipemdLength.RIPEMD_160, cycles);
  }

  /**
   * Ripemd散列摘要算法，默认编码UTF-8，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @param length    Ripemd算法长度
   * @see Digests#ripemd(String, RipemdLength, int)
   */
  public static String ripemd(String plaintext, RipemdLength length) {
    return ripemd(plaintext, StandardCharsets.UTF_8, length, 1);
  }

  /**
   * Ripemd散列摘要算法，默认编码UTF-8
   *
   * @param plaintext 需要做摘要的字符串
   * @param length    Ripemd算法长度
   * @param cycles    散列摘要次数
   * @see Digests#ripemd(String, RipemdLength, int)
   */
  public static String ripemd(String plaintext, RipemdLength length, int cycles) {
    return ripemd(plaintext, StandardCharsets.UTF_8, length, cycles);
  }

  /**
   * Ripemd散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param charset   字符编码
   * @param length    Ripemd算法长度
   * @param cycles    散列摘要次数
   * @see Digests#ripemd(String, RipemdLength, int)
   */
  public static String ripemd(String plaintext, Charset charset, RipemdLength length, int cycles) {
    return ripemd(plaintext.getBytes(charset), length, cycles);
  }

  /**
   * Ripemd散列摘要算法，默认算法长度为RIPEMD_160，默认摘要次数 1
   *
   * @param obj 需要做摘要的任意类实例
   * @see Digests#ripemd(Object, RipemdLength, int)
   */
  public static String ripemd(Object obj) {
    return ripemd(obj, RipemdLength.RIPEMD_160, 1);
  }

  /**
   * Ripemd散列摘要算法，默认算法长度为RIPEMD_160
   *
   * @param obj    需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   * @see Digests#ripemd(Object, RipemdLength, int)
   */
  public static String ripemd(Object obj, int cycles) {
    return ripemd(obj, RipemdLength.RIPEMD_160, cycles);
  }

  /**
   * Ripemd散列摘要算法，默认摘要次数 1
   *
   * @param obj    需要做摘要的任意类实例
   * @param length Ripemd算法长度
   * @see Digests#ripemd(Object, RipemdLength, int)
   */
  public static String ripemd(Object obj, RipemdLength length) {
    return ripemd(obj, length, 1);
  }

  /**
   * Ripemd散列摘要算法
   *
   * @param obj    需要做摘要的任意类实例
   * @param length Ripemd算法长度
   * @param cycles 散列摘要次数
   * @see Digests#ripemd(Object, RipemdLength, int)
   */
  public static String ripemd(Object obj, RipemdLength length, int cycles) {
    return ripemd(Bytes.objectToBytes(obj), length, cycles);
  }

  /**
   * Ripemd散列摘要算法，默认算法长度为RIPEMD_160，默认摘要次数 1
   *
   * @param file 需要做摘要的文件
   * @see Digests#ripemd(File, RipemdLength, int)
   */
  public static String ripemd(File file) {
    return ripemd(file, RipemdLength.RIPEMD_160, 1);
  }

  /**
   * Ripemd散列摘要算法，默认算法长度为RIPEMD_160
   *
   * @param file   需要做摘要的文件
   * @param cycles 散列摘要次数
   * @see Digests#ripemd(File, RipemdLength, int)
   */
  public static String ripemd(File file, int cycles) {
    return ripemd(file, RipemdLength.RIPEMD_160, cycles);
  }

  /**
   * Ripemd散列摘要算法，默认摘要次数 1
   *
   * @param file   需要做摘要的文件
   * @param length Ripemd算法长度
   * @see Digests#ripemd(File, RipemdLength, int)
   */
  public static String ripemd(File file, RipemdLength length) {
    return ripemd(file, length, 1);
  }

  /**
   * Ripemd散列摘要算法
   *
   * @param file   需要做摘要的文件
   * @param length Ripemd算法长度
   * @param cycles 散列摘要次数
   * @see Digests#ripemd(File, RipemdLength, int)
   */
  public static String ripemd(File file, RipemdLength length, int cycles) throws FileException {
    if (file == null || !file.exists() || !file.isFile()) {
      throw new FileException("请确保文件正确: {}", file);
    }
    try {
      return ripemd(Files.readAllBytes(file.toPath()), length, cycles);
    } catch (IOException e) {
      throw new FileException(e, "无法读取文件: {}", file);
    }
  }

  /**
   * Ripemd散列摘要算法，默认算法长度为RIPEMD_160，默认摘要次数 1
   *
   * @param bytes 需要做摘要的字节数组
   * @see Digests#ripemd(byte[], RipemdLength, int)
   */
  public static String ripemd(byte[] bytes) {
    return ripemd(bytes, RipemdLength.RIPEMD_160, 1);
  }

  /**
   * Ripemd散列摘要算法，默认算法长度为RIPEMD_160
   *
   * @param bytes  需要做摘要的字节数组
   * @param cycles 散列摘要次数
   * @see Digests#ripemd(byte[], RipemdLength, int)
   */
  public static String ripemd(byte[] bytes, int cycles) {
    return ripemd(bytes, RipemdLength.RIPEMD_160, cycles);
  }

  /**
   * Ripemd散列摘要算法，默认摘要次数 1
   *
   * @param bytes  需要做摘要的字节数组
   * @param length Ripemd算法长度
   * @see Digests#ripemd(byte[], RipemdLength, int)
   */
  public static String ripemd(byte[] bytes, RipemdLength length) {
    return ripemd(bytes, length, 1);
  }

  /**
   * Ripemd散列摘要算法
   *
   * @param bytes  需要做摘要的字节数组
   * @param length Ripemd算法长度
   * @param cycles 散列摘要次数
   */
  public static String ripemd(byte[] bytes, RipemdLength length, int cycles) {
    BCMessageDigest digester;
    switch (length) {
      case RIPEMD_128 -> digester = RIPEMD128_DIGEST.get();
      case RIPEMD_160 -> digester = RIPEMD160_DIGEST.get();
      case RIPEMD_256 -> digester = RIPEMD256_DIGEST.get();
      case RIPEMD_320 -> digester = RIPEMD320_DIGEST.get();
      default -> throw new IllegalArgumentException("Unknown ripemd-length: " + length);
    }

    digester.update(bytes);
    byte[] digested = digester.digest();
    digester.reset();

    if (cycles == 1) {
      return Hex.toHexString(digested);
    }
    return ripemd(digested, length, cycles - 1);
  }

  // ===================================================================================================================

  /**
   * 国密SM3散列摘要算法，默认字符编码UTF-8，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#sm3(String, Charset, int)
   */
  public static String sm3(String plaintext) {
    return sm3(plaintext, StandardCharsets.UTF_8, 1);
  }

  /**
   * 国密SM3散列摘要算法，默认字符编码UTF-8
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#sm3(String, Charset, int)
   */
  public static String sm3(String plaintext, int cycles) {
    return sm3(plaintext, StandardCharsets.UTF_8, cycles);
  }

  /**
   * 国密SM3散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param charset   字符编码
   * @param cycles    散列摘要次数
   */
  public static String sm3(String plaintext, Charset charset, int cycles) {
    return sm3(plaintext.getBytes(charset), cycles);
  }

  /**
   * 国密SM3散列摘要算法，默认摘要次数 1
   *
   * @param obj 需要做摘要的任意类实例
   * @see Digests#sm3(Object, int)
   */
  public static String sm3(Object obj) {
    return sm3(obj, 1);
  }

  /**
   * 国密SM3散列摘要算法
   *
   * @param obj    需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   */
  public static String sm3(Object obj, int cycles) {
    return sm3(Bytes.objectToBytes(obj), cycles);
  }

  /**
   * 国密SM3散列摘要算法，默认摘要次数 1
   *
   * @param file 需要做摘要的文件
   * @see Digests#sm3(File, int)
   */
  public static String sm3(File file) {
    return sm3(file, 1);
  }

  /**
   * 国密SM3散列摘要算法
   *
   * @param file   需要做摘要的文件
   * @param cycles 散列摘要次数
   */
  public static String sm3(File file, int cycles) throws FileException {
    if (file == null || !file.exists() || !file.isFile()) {
      throw new FileException("请确保文件正确: {}", file);
    }
    try {
      return sm3(Files.readAllBytes(file.toPath()), cycles);
    } catch (IOException e) {
      throw new FileException(e, "无法读取文件: {}", file);
    }
  }

  /**
   * 国密SM3散列摘要算法，默认摘要次数 1
   *
   * @param bytes 需要做摘要的字节数组
   * @see Digests#sm3(byte[], int)
   */
  public static String sm3(byte[] bytes) {
    return sm3(bytes, 1);
  }

  /**
   * 国密SM3散列摘要算法
   *
   * @param bytes  需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  public static String sm3(byte[] bytes, int cycles) {
    BCMessageDigest digest = SM3_DIGEST.get();
    digest.update(bytes);
    byte[] digested = digest.digest();
    digest.reset();

    if (cycles == 1) {
      return Hex.toHexString(digested);
    }
    return sm3(digested, cycles - 1);
  }

  // ===================================================================================================================

  /**
   * Tiger散列摘要算法，默认字符编码UTF-8，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#tiger(String, Charset, int)
   */
  public static String tiger(String plaintext) {
    return tiger(plaintext, StandardCharsets.UTF_8, 1);
  }

  /**
   * Tiger散列摘要算法，默认字符编码UTF-8
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#tiger(String, Charset, int)
   */
  public static String tiger(String plaintext, int cycles) {
    return tiger(plaintext, StandardCharsets.UTF_8, cycles);
  }

  /**
   * Tiger散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param charset   字符编码
   * @param cycles    散列摘要次数
   */
  public static String tiger(String plaintext, Charset charset, int cycles) {
    return tiger(plaintext.getBytes(charset), cycles);
  }

  /**
   * Tiger散列摘要算法，默认摘要次数 1
   *
   * @param obj 需要做摘要的任意类实例
   * @see Digests#tiger(Object, int)
   */
  public static String tiger(Object obj) {
    return tiger(obj, 1);
  }

  /**
   * Tiger散列摘要算法
   *
   * @param obj    需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   */
  public static String tiger(Object obj, int cycles) {
    return tiger(Bytes.objectToBytes(obj), cycles);
  }

  /**
   * Tiger散列摘要算法，默认摘要次数 1
   *
   * @param file 需要做摘要的文件
   * @see Digests#tiger(File, int)
   */
  public static String tiger(File file) {
    return tiger(file, 1);
  }

  /**
   * Tiger散列摘要算法
   *
   * @param file   需要做摘要的文件
   * @param cycles 散列摘要次数
   */
  public static String tiger(File file, int cycles) throws FileException {
    if (file == null || !file.exists() || !file.isFile()) {
      throw new FileException("请确保文件正确: {}", file);
    }
    try {
      return tiger(Files.readAllBytes(file.toPath()), cycles);
    } catch (IOException e) {
      throw new FileException(e, "无法读取文件: {}", file);
    }
  }

  /**
   * Tiger散列摘要算法，默认摘要次数 1
   *
   * @param bytes 需要做摘要的字节数组
   * @see Digests#tiger(byte[], int)
   */
  public static String tiger(byte[] bytes) {
    return tiger(bytes, 1);
  }

  /**
   * Tiger散列摘要算法
   *
   * @param bytes  需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  public static String tiger(byte[] bytes, int cycles) {
    BCMessageDigest digest = TIGER_DIGEST.get();
    digest.update(bytes);
    byte[] digested = digest.digest();
    digest.reset();

    if (cycles == 1) {
      return Hex.toHexString(digested);
    }
    return tiger(digested, cycles - 1);
  }

  // ===================================================================================================================

  /**
   * Whirlpool散列摘要算法，默认字符编码UTF-8，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#whirlpool(String, Charset, int)
   */
  public static String whirlpool(String plaintext) {
    return whirlpool(plaintext, StandardCharsets.UTF_8, 1);
  }

  /**
   * Whirlpool散列摘要算法，默认字符编码UTF-8
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#whirlpool(String, Charset, int)
   */
  public static String whirlpool(String plaintext, int cycles) {
    return whirlpool(plaintext, StandardCharsets.UTF_8, cycles);
  }

  /**
   * Whirlpool散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param charset   字符编码
   * @param cycles    散列摘要次数
   */
  public static String whirlpool(String plaintext, Charset charset, int cycles) {
    return whirlpool(plaintext.getBytes(charset), cycles);
  }

  /**
   * Whirlpool散列摘要算法，默认摘要次数 1
   *
   * @param obj 需要做摘要的任意类实例
   * @see Digests#whirlpool(Object, int)
   */
  public static String whirlpool(Object obj) {
    return whirlpool(obj, 1);
  }

  /**
   * Whirlpool散列摘要算法
   *
   * @param obj    需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   */
  public static String whirlpool(Object obj, int cycles) {
    return whirlpool(Bytes.objectToBytes(obj), cycles);
  }

  /**
   * Whirlpool散列摘要算法，默认摘要次数 1
   *
   * @param file 需要做摘要的文件
   * @see Digests#whirlpool(File, int)
   */
  public static String whirlpool(File file) {
    return whirlpool(file, 1);
  }

  /**
   * Whirlpool散列摘要算法
   *
   * @param file   需要做摘要的文件
   * @param cycles 散列摘要次数
   */
  public static String whirlpool(File file, int cycles) throws FileException {
    if (file == null || !file.exists() || !file.isFile()) {
      throw new FileException("请确保文件正确: {}", file);
    }
    try {
      return whirlpool(Files.readAllBytes(file.toPath()), cycles);
    } catch (IOException e) {
      throw new FileException(e, "无法读取文件: {}", file);
    }
  }

  /**
   * Whirlpool散列摘要算法，默认摘要次数 1
   *
   * @param bytes 需要做摘要的字节数组
   * @see Digests#whirlpool(byte[], int)
   */
  public static String whirlpool(byte[] bytes) {
    return whirlpool(bytes, 1);
  }

  /**
   * Whirlpool散列摘要算法
   *
   * @param bytes  需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  public static String whirlpool(byte[] bytes, int cycles) {
    BCMessageDigest digest = WHIRLPOOL_DIGEST.get();
    digest.update(bytes);
    byte[] digested = digest.digest();
    digest.reset();

    if (cycles == 1) {
      return Hex.toHexString(digested);
    }
    return whirlpool(digested, cycles - 1);
  }

  // ===================================================================================================================

  /**
   * MD5散列摘要算法，默认字符编码UTF-8，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#md5(String, Charset, int)
   */
  public static String md5(String plaintext) {
    return md5(plaintext, StandardCharsets.UTF_8, 1);
  }

  /**
   * MD5散列摘要算法，默认字符编码UTF-8
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#md5(String, Charset, int)
   */
  public static String md5(String plaintext, int cycles) {
    return md5(plaintext, StandardCharsets.UTF_8, cycles);
  }

  /**
   * MD5散列摘要算法
   *
   * @param plaintext 需要做摘要的字节数组
   * @param charset   字符编码
   * @param cycles    散列摘要次数
   */
  public static String md5(String plaintext, Charset charset, int cycles) {
    return md5(plaintext.getBytes(charset), cycles);
  }

  /**
   * MD5散列摘要算法，默认摘要次数 1
   *
   * @param obj 需要做摘要的任意类实例
   * @see Digests#md5(Object, int)
   */
  public static String md5(Object obj) {
    return md5(obj, 1);
  }

  /**
   * MD5散列摘要算法
   *
   * @param obj    需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   */
  public static String md5(Object obj, int cycles) {
    return md5(Bytes.objectToBytes(obj), cycles);
  }

  /**
   * MD5散列摘要算法，默认摘要次数 1
   *
   * @param file 需要做摘要的文件
   * @see Digests#md5(File, int)
   */
  public static String md5(File file) {
    return md5(file, 1);
  }

  /**
   * MD5散列摘要算法
   *
   * @param file   需要做摘要的文件
   * @param cycles 散列摘要次数
   */
  public static String md5(File file, int cycles) throws FileException {
    if (file == null || !file.exists() || !file.isFile()) {
      throw new FileException("请确保文件正确: {}", file);
    }
    try {
      return md5(Files.readAllBytes(file.toPath()), cycles);
    } catch (IOException e) {
      throw new FileException(e, "无法读取文件: {}", file);
    }
  }

  /**
   * MD5散列摘要算法，默认摘要次数 1
   *
   * @param bytes 需要做摘要的字节数组
   * @see Digests#md5(byte[], int)
   */
  public static String md5(byte[] bytes) {
    return md5(bytes, 1);
  }

  /**
   * MD5散列摘要算法
   *
   * @param bytes  需要做摘要的字节数组
   * @param cycles 散列摘要次数
   */
  public static String md5(byte[] bytes, int cycles) {
    BCMessageDigest digest = MD5_DIGEST.get();
    digest.update(bytes);
    byte[] digested = digest.digest();
    digest.reset();

    if (cycles == 1) {
      return Hex.toHexString(digested);
    }
    return md5(digested, cycles - 1);
  }

  // ===================================================================================================================

  public enum SHALength {
    SHA_224, SHA_256, SHA_384, SHA_512
  }

  /**
   * SHA-2散列摘要算法，默认编码UTF-8，默认算法长度为SHA-256，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#sha2(String, SHALength, int)
   */
  public static String sha2(String plaintext) {
    return sha2(plaintext, StandardCharsets.UTF_8, SHALength.SHA_256, 1);
  }

  /**
   * SHA-2散列摘要算法，默认编码UTF-8，默认算法长度为SHA-256
   *
   * @param plaintext 需要做摘要的字符串
   * @param cycles    散列摘要次数
   * @see Digests#sha2(String, SHALength, int)
   */
  public static String sha2(String plaintext, int cycles) {
    return sha2(plaintext, StandardCharsets.UTF_8, SHALength.SHA_256, cycles);
  }

  /**
   * SHA-2散列摘要算法，默认编码UTF-8，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @param length    SHA-2算法长度
   * @see Digests#sha2(String, SHALength, int)
   */
  public static String sha2(String plaintext, SHALength length) {
    return sha2(plaintext, StandardCharsets.UTF_8, length, 1);
  }

  /**
   * SHA-2散列摘要算法，默认编码UTF-8
   *
   * @param plaintext 需要做摘要的字符串
   * @param length    SHA-2算法长度
   * @param cycles    散列摘要次数
   * @see Digests#sha2(String, SHALength, int)
   */
  public static String sha2(String plaintext, SHALength length, int cycles) {
    return sha2(plaintext, StandardCharsets.UTF_8, length, cycles);
  }

  /**
   * SHA-2散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param charset   字符编码
   * @param length    SHA-2算法长度
   * @param cycles    散列摘要次数
   * @see Digests#sha2(String, SHALength, int)
   */
  public static String sha2(String plaintext, Charset charset, SHALength length, int cycles) {
    return sha2(plaintext.getBytes(charset), length, cycles);
  }

  /**
   * SHA-2散列摘要算法，默认算法长度为SHA-256，默认摘要次数 1
   *
   * @param obj 需要做摘要的任意类实例
   * @see Digests#sha2(Object, SHALength, int)
   */
  public static String sha2(Object obj) {
    return sha2(obj, SHALength.SHA_256, 1);
  }

  /**
   * SHA-2散列摘要算法，默认算法长度为SHA-256
   *
   * @param obj    需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   * @see Digests#sha2(Object, SHALength, int)
   */
  public static String sha2(Object obj, int cycles) {
    return sha2(obj, SHALength.SHA_256, cycles);
  }

  /**
   * SHA-2散列摘要算法，默认摘要次数 1
   *
   * @param obj    需要做摘要的任意类实例
   * @param length SHA-2算法长度
   * @see Digests#sha2(Object, SHALength, int)
   */
  public static String sha2(Object obj, SHALength length) {
    return sha2(obj, length, 1);
  }

  /**
   * SHA-2散列摘要算法
   *
   * @param obj    需要做摘要的任意类实例
   * @param length SHA-2算法长度
   * @param cycles 散列摘要次数
   * @see Digests#sha2(Object, SHALength, int)
   */
  public static String sha2(Object obj, SHALength length, int cycles) {
    return sha2(Bytes.objectToBytes(obj), length, cycles);
  }

  /**
   * SHA-2散列摘要算法，默认算法长度为SHA-256，默认摘要次数 1
   *
   * @param file 需要做摘要的文件
   * @see Digests#sha2(File, SHALength, int)
   */
  public static String sha2(File file) {
    return sha2(file, SHALength.SHA_256, 1);
  }

  /**
   * SHA-2散列摘要算法，默认算法长度为SHA-256
   *
   * @param file   需要做摘要的文件
   * @param cycles 散列摘要次数
   * @see Digests#sha2(File, SHALength, int)
   */
  public static String sha2(File file, int cycles) {
    return sha2(file, SHALength.SHA_256, cycles);
  }

  /**
   * SHA-2散列摘要算法，默认摘要次数 1
   *
   * @param file   需要做摘要的文件
   * @param length SHA-2算法长度
   * @see Digests#sha2(File, SHALength, int)
   */
  public static String sha2(File file, SHALength length) {
    return sha2(file, length, 1);
  }

  /**
   * SHA-2散列摘要算法
   *
   * @param file   需要做摘要的文件
   * @param length SHA-2算法长度
   * @param cycles 散列摘要次数
   * @see Digests#sha2(File, SHALength, int)
   */
  public static String sha2(File file, SHALength length, int cycles) throws FileException {
    if (file == null || !file.exists() || !file.isFile()) {
      throw new FileException("请确保文件正确: {}", file);
    }
    try {
      return sha2(Files.readAllBytes(file.toPath()), length, cycles);
    } catch (IOException e) {
      throw new FileException(e, "无法读取文件: {}", file);
    }
  }

  /**
   * SHA-2散列摘要算法，默认算法长度为SHA-256，默认摘要次数 1
   *
   * @param bytes 需要做摘要的字节数组
   * @see Digests#sha2(byte[], SHALength, int)
   */
  public static String sha2(byte[] bytes) {
    return sha2(bytes, SHALength.SHA_256, 1);
  }

  /**
   * SHA-2散列摘要算法，默认算法长度为SHA-256
   *
   * @param bytes  需要做摘要的字节数组
   * @param cycles 散列摘要次数
   * @see Digests#sha2(byte[], SHALength, int)
   */
  public static String sha2(byte[] bytes, int cycles) {
    return sha2(bytes, SHALength.SHA_256, cycles);
  }

  /**
   * SHA-2散列摘要算法，默认摘要次数 1
   *
   * @param bytes  需要做摘要的字节数组
   * @param length SHA-2算法长度
   * @see Digests#sha2(byte[], SHALength, int)
   */
  public static String sha2(byte[] bytes, SHALength length) {
    return sha2(bytes, length, 1);
  }

  /**
   * SHA-2散列摘要算法
   *
   * @param bytes  需要做摘要的字节数组
   * @param length SHA-2算法长度
   * @param cycles 散列摘要次数
   */
  public static String sha2(byte[] bytes, SHALength length, int cycles) {
    BCMessageDigest digester;
    switch (length) {
      case SHA_224 -> digester = SHA2_224_DIGEST.get();
      case SHA_256 -> digester = SHA2_256_DIGEST.get();
      case SHA_384 -> digester = SHA2_384_DIGEST.get();
      case SHA_512 -> digester = SHA2_512_DIGEST.get();
      default -> throw new IllegalArgumentException("Unknown sha2-length: " + length);
    }

    digester.update(bytes);
    byte[] digested = digester.digest();
    digester.reset();

    if (cycles == 1) {
      return Hex.toHexString(digested);
    }
    return sha2(digested, length, cycles - 1);
  }

  // ===================================================================================================================

  /**
   * SHA-3散列摘要算法，默认编码UTF-8，默认算法长度为SHA-256，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @see Digests#sha3(String, SHALength, int)
   */
  public static String sha3(String plaintext) {
    return sha3(plaintext, StandardCharsets.UTF_8, SHALength.SHA_256, 1);
  }

  /**
   * SHA-3散列摘要算法，默认编码UTF-8，默认算法长度为SHA-256
   *
   * @param plaintext 需要做摘要的字符串
   * @param cycles    散列摘要次数
   * @see Digests#sha3(String, SHALength, int)
   */
  public static String sha3(String plaintext, int cycles) {
    return sha3(plaintext, StandardCharsets.UTF_8, SHALength.SHA_256, cycles);
  }

  /**
   * SHA-3散列摘要算法，默认编码UTF-8，默认摘要次数 1
   *
   * @param plaintext 需要做摘要的字符串
   * @param length    SHA-3算法长度
   * @see Digests#sha3(String, SHALength, int)
   */
  public static String sha3(String plaintext, SHALength length) {
    return sha3(plaintext, StandardCharsets.UTF_8, length, 1);
  }

  /**
   * SHA-3散列摘要算法，默认编码UTF-8
   *
   * @param plaintext 需要做摘要的字符串
   * @param length    SHA-3算法长度
   * @param cycles    散列摘要次数
   * @see Digests#sha3(String, SHALength, int)
   */
  public static String sha3(String plaintext, SHALength length, int cycles) {
    return sha3(plaintext, StandardCharsets.UTF_8, length, cycles);
  }

  /**
   * SHA-3散列摘要算法
   *
   * @param plaintext 需要做摘要的字符串
   * @param charset   字符编码
   * @param length    SHA-3算法长度
   * @param cycles    散列摘要次数
   * @see Digests#sha3(String, SHALength, int)
   */
  public static String sha3(String plaintext, Charset charset, SHALength length, int cycles) {
    return sha3(plaintext.getBytes(charset), length, cycles);
  }

  /**
   * SHA-3散列摘要算法，默认算法长度为SHA-256，默认摘要次数 1
   *
   * @param obj 需要做摘要的任意类实例
   * @see Digests#sha3(Object, SHALength, int)
   */
  public static String sha3(Object obj) {
    return sha3(obj, SHALength.SHA_256, 1);
  }

  /**
   * SHA-3散列摘要算法，默认算法长度为SHA-256
   *
   * @param obj    需要做摘要的任意类实例
   * @param cycles 散列摘要次数
   * @see Digests#sha3(Object, SHALength, int)
   */
  public static String sha3(Object obj, int cycles) {
    return sha3(obj, SHALength.SHA_256, cycles);
  }

  /**
   * SHA-3散列摘要算法，默认摘要次数 1
   *
   * @param obj    需要做摘要的任意类实例
   * @param length SHA-3算法长度
   * @see Digests#sha3(Object, SHALength, int)
   */
  public static String sha3(Object obj, SHALength length) {
    return sha3(obj, length, 1);
  }

  /**
   * SHA-3散列摘要算法
   *
   * @param obj    需要做摘要的任意类实例
   * @param length SHA-3算法长度
   * @param cycles 散列摘要次数
   * @see Digests#sha3(Object, SHALength, int)
   */
  public static String sha3(Object obj, SHALength length, int cycles) {
    return sha3(Bytes.objectToBytes(obj), length, cycles);
  }

  /**
   * SHA-3散列摘要算法，默认算法长度为SHA-256，默认摘要次数 1
   *
   * @param file 需要做摘要的文件
   * @see Digests#sha3(File, SHALength, int)
   */
  public static String sha3(File file) {
    return sha3(file, SHALength.SHA_256, 1);
  }

  /**
   * SHA-3散列摘要算法，默认算法长度为SHA-256
   *
   * @param file   需要做摘要的文件
   * @param cycles 散列摘要次数
   * @see Digests#sha3(File, SHALength, int)
   */
  public static String sha3(File file, int cycles) {
    return sha3(file, SHALength.SHA_256, cycles);
  }

  /**
   * SHA-3散列摘要算法，默认摘要次数 1
   *
   * @param file   需要做摘要的文件
   * @param length SHA-3算法长度
   * @see Digests#sha3(File, SHALength, int)
   */
  public static String sha3(File file, SHALength length) {
    return sha3(file, length, 1);
  }

  /**
   * SHA-3散列摘要算法
   *
   * @param file   需要做摘要的文件
   * @param length SHA-3算法长度
   * @param cycles 散列摘要次数
   * @see Digests#sha3(File, SHALength, int)
   */
  public static String sha3(File file, SHALength length, int cycles) throws FileException {
    if (file == null || !file.exists() || !file.isFile()) {
      throw new FileException("请确保文件正确: {}", file);
    }
    try {
      return sha3(Files.readAllBytes(file.toPath()), length, cycles);
    } catch (IOException e) {
      throw new FileException(e, "无法读取文件: {}", file);
    }
  }

  /**
   * SHA-3散列摘要算法，默认算法长度为SHA-256，默认摘要次数 1
   *
   * @param bytes 需要做摘要的字节数组
   * @see Digests#sha3(byte[], SHALength, int)
   */
  public static String sha3(byte[] bytes) {
    return sha3(bytes, SHALength.SHA_256, 1);
  }

  /**
   * SHA-3散列摘要算法，默认算法长度为SHA-256
   *
   * @param bytes  需要做摘要的字节数组
   * @param cycles 散列摘要次数
   * @see Digests#sha3(byte[], SHALength, int)
   */
  public static String sha3(byte[] bytes, int cycles) {
    return sha3(bytes, SHALength.SHA_256, cycles);
  }

  /**
   * SHA-3散列摘要算法，默认摘要次数 1
   *
   * @param bytes  需要做摘要的字节数组
   * @param length SHA-3算法长度
   * @see Digests#sha3(byte[], SHALength, int)
   */
  public static String sha3(byte[] bytes, SHALength length) {
    return sha3(bytes, length, 1);
  }

  /**
   * SHA-3散列摘要算法
   *
   * @param bytes  需要做摘要的字节数组
   * @param length SHA-3算法长度
   * @param cycles 散列摘要次数
   */
  public static String sha3(byte[] bytes, SHALength length, int cycles) {
    BCMessageDigest digester;
    switch (length) {
      case SHA_224 -> digester = SHA3_224_DIGEST.get();
      case SHA_256 -> digester = SHA3_256_DIGEST.get();
      case SHA_384 -> digester = SHA3_384_DIGEST.get();
      case SHA_512 -> digester = SHA3_512_DIGEST.get();
      default -> throw new IllegalArgumentException("Unknown sha3-length: " + length);
    }

    digester.update(bytes);
    byte[] digested = digester.digest();
    digester.reset();

    if (cycles == 1) {
      return Hex.toHexString(digested);
    }
    return sha3(digested, length, cycles - 1);
  }
}
