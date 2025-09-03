package cn.labzen.algorithm.binary;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public final class ChaoticBase90 {

  private static final char[] ASCII_CHARS = "p^QrsnkvzS[:c;>TDljM%FiLh)e2y<XAU*}+49#,O5w_&HZ6m7?Ko03=EuGdYIJ!Wa]gx1f(B{R@VC|N-P8\\$.qb~t`".toCharArray();

  private static final Map<Character, Integer> ASCII_MAPPING;

  static {
    Map<Character, Integer> map = new HashMap<>();
    for (int i = 0; i < ASCII_CHARS.length; i++) {
      map.put(ASCII_CHARS[i], i);
    }
    ASCII_MAPPING = Collections.unmodifiableMap(map);
  }

  private static final int[] BASE90_POWER = {1, 90, 90 * 90, 90 * 90 * 90, 90 * 90 * 90 * 90};

  private ChaoticBase90() {
  }

  public static String encode(String originalText) {
    return encode(originalText.getBytes(StandardCharsets.UTF_8));
  }

  public static String encode(byte[] originalTextBytes) {
    // By using five ASCII characters to represent four bytes of binary data the encoded size ¹⁄₄ is larger than the original
    StringBuilder sb = new StringBuilder(originalTextBytes.length * 5 / 4);
    byte[] chunk = new byte[4];
    int index = 0;

    for (byte b : originalTextBytes) {
      chunk[index++] = b;

      if (index == 4) {
        int value = byteToInt(chunk);
        sb.append(encodeChunk(value));
        Arrays.fill(chunk, (byte) 0);
        index = 0;
      }
    }

    // If we didn't end on 0, then we need some padding
    if (index > 0) {
      int paddedSize = chunk.length - index;
      Arrays.fill(chunk, index, chunk.length, (byte) 0);
      int value = byteToInt(chunk);
      char[] encodedChunk = encodeChunk(value);
      for (int i = 0; i < encodedChunk.length - paddedSize; i++) {
        sb.append(encodedChunk[i]);
      }
    }

    return sb.toString();
  }

  private static char[] encodeChunk(int value) {
    long longValue = value & 0x00000000ffffffffL;
    char[] encodedChunk = new char[5];
    for (int i = 0; i < encodedChunk.length; i++) {
      int ci = (int) (longValue / BASE90_POWER[4 - i]);
      encodedChunk[i] = ASCII_CHARS[ci];
      longValue %= BASE90_POWER[4 - i];
    }
    return encodedChunk;
  }

  public static String decode(String encodedText) {
    return decode(encodedText.getBytes(StandardCharsets.UTF_8));
  }

  public static String decode(byte[] encodedTextBytes) {
    int textSize = encodedTextBytes.length;

    // 计算解码后的字节大小 (原来的 BigDecimal 换成整数运算)
    int decodeSize = textSize * 4 / 5;
    ByteBuffer buffer = ByteBuffer.allocate(decodeSize);

    byte[] chunk = new byte[5];
    int index = 0;

    for (byte b : encodedTextBytes) {
      chunk[index++] = b;

      if (index == 5) {
        buffer.put(decodeChunk(chunk));
        Arrays.fill(chunk, (byte) 0);
        index = 0;
      }
    }

    // 处理不足 5 个字节的尾部
    if (index > 0) {
      int paddedSize = chunk.length - index;
      Arrays.fill(chunk, index, chunk.length, (byte) '`'); // 用 '`' 填充
      byte[] paddedDecode = decodeChunk(chunk);
      for (int i = 0; i < paddedDecode.length - paddedSize; i++) {
        buffer.put(paddedDecode[i]);
      }
    }

    buffer.flip();
    byte[] decoded = Arrays.copyOf(buffer.array(), buffer.limit());
    return new String(decoded, StandardCharsets.UTF_8);
  }

  private static byte[] decodeChunk(byte[] chunk) {
    if (chunk.length != 5) {
      throw new IllegalArgumentException("You can only decode chunks of size 5.");
    }
    int value = 0;
    value += ASCII_MAPPING.get((char) chunk[0]) * BASE90_POWER[4];
    value += ASCII_MAPPING.get((char) chunk[1]) * BASE90_POWER[3];
    value += ASCII_MAPPING.get((char) chunk[2]) * BASE90_POWER[2];
    value += ASCII_MAPPING.get((char) chunk[3]) * BASE90_POWER[1];
    value += ASCII_MAPPING.get((char) chunk[4]) * BASE90_POWER[0];

    return intToByte(value);
  }

  private static int byteToInt(byte[] value) {
    if (value.length != 4) {
      throw new IllegalArgumentException("Cannot create an int without exactly 4 bytes.");
    }
    return ByteBuffer.wrap(value).getInt();
  }

  private static byte[] intToByte(int value) {
    return new byte[]{(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
  }
}
