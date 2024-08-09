package cn.labzen.algorithm.binary

import java.math.BigDecimal
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.*

object ChaoticBase90 {

  private val ASCII_CHARS = let {
    """p^QrsnkvzS[:c;>TDljM%FiLh)e2y<XAU*}+49#,O5w_&HZ6m7?Ko03=EuGdYIJ!Wa]gx1f(B{R@VC|N-P8\$.qb~t`""".toCharArray()
  }
  private val ASCII_MAPPING = let {
    ASCII_CHARS.mapIndexed { i, c -> c to i }.toMap()
  }
  private val BASE90_POWER = arrayOf(1, 90, 90 * 90, 90 * 90 * 90, 90 * 90 * 90 * 90)

  @JvmStatic
  fun encode(originalText: String): String =
    encode(originalText.toByteArray(StandardCharsets.UTF_8))

  @JvmStatic
  fun encode(originalTextBytes: ByteArray): String {
    // By using five ASCII characters to represent four bytes of binary data the encoded size ¹⁄₄ is larger than the original
    val sb = StringBuilder(originalTextBytes.size * (5 / 4))
    val chunk = ByteArray(4)
    var index = 0

    originalTextBytes.forEach {
      chunk[index++] = it

      if (index == 4) {
        val value = byteToInt(chunk)
        sb.append(encodeChunk(value))
        Arrays.fill(chunk, 0)
        index = 0
      }
    }

    // If we didn't end on 0, then we need some padding
    if (index > 0) {
      val paddedSize = chunk.size - index
      Arrays.fill(chunk, index, chunk.size, 0)
      val value = byteToInt(chunk)
      val encodedChunk = encodeChunk(value)
      for (i in 0 until (encodedChunk.size - paddedSize)) {
        sb.append(encodedChunk[i])
      }
    }

    return sb.toString()
  }

  private fun encodeChunk(value: Int): CharArray {
    var longValue = value.toLong() and 0x00000000ffffffffL
    val encodedChunk = CharArray(5)
    for (i in encodedChunk.indices) {
      val ci = (longValue / BASE90_POWER[4 - i]).toInt()
      encodedChunk[i] = ASCII_CHARS[ci]
      longValue %= BASE90_POWER[4 - i]
    }
    return encodedChunk
  }

  @JvmStatic
  fun decode(encodedText: String): String =
    decode(encodedText.toByteArray(StandardCharsets.UTF_8))

  @JvmStatic
  fun decode(encodedTextBytes: ByteArray): String {
    val textSize: Int = encodedTextBytes.size

    val decodeSize = BigDecimal.valueOf(textSize.toLong())
      .multiply(BigDecimal.valueOf(4))
      .divide(BigDecimal.valueOf(5))
    val buffer = ByteBuffer.allocate(decodeSize.toInt())
    val chunk = ByteArray(5)
    var index = 0

    encodedTextBytes.forEach {
      chunk[index++] = it

      if (index == 5) {
        buffer.put(decodeChunk(chunk))
        Arrays.fill(chunk, 0)
        index = 0
      }
    }

    // If we didn't end on 0, then we need some padding
    if (index > 0) {
      val paddedSize: Int = chunk.size - index
      Arrays.fill(chunk, index, chunk.size, '`'.code.toByte())
      val paddedDecode: ByteArray = decodeChunk(chunk)
      for (i in 0 until (paddedDecode.size - paddedSize)) {
        buffer.put(paddedDecode[i])
      }
    }

    buffer.flip()
    val decoded = Arrays.copyOf(buffer.array(), buffer.limit())
    return String(decoded)
  }

  private fun decodeChunk(chunk: ByteArray): ByteArray {
    require(chunk.size == 5) { "You can only decode chunks of size 5." }
    var value = 0
    value += ASCII_MAPPING[chunk[0].toInt().toChar()]!! * BASE90_POWER[4]
    value += ASCII_MAPPING[chunk[1].toInt().toChar()]!! * BASE90_POWER[3]
    value += ASCII_MAPPING[chunk[2].toInt().toChar()]!! * BASE90_POWER[2]
    value += ASCII_MAPPING[chunk[3].toInt().toChar()]!! * BASE90_POWER[1]
    value += ASCII_MAPPING[chunk[4].toInt().toChar()]!! * BASE90_POWER[0]

    return intToByte(value)
  }

  private fun byteToInt(value: ByteArray): Int {
    require(value.size == 4) { "Cannot create an int without exactly 4 bytes." }
    return ByteBuffer.wrap(value).getInt()
  }

  private fun intToByte(value: Int): ByteArray {
    return byteArrayOf((value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte())
  }
}
