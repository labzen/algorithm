package cn.labzen.algorithm.binary;

import cn.labzen.tool.util.Randoms;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Random;

public class ChaoticBase90Test {

  @Test
  public void test() {
    int times = 10000;
    while (times-- > 0) {
      int len = Randoms.intNumber(10, 100);
      int mid = Randoms.intNumber(5, len);

      String originalText = Randoms.string(mid) + generateRandomChinese(len - mid);
      System.out.println(times + " - " + originalText);

      String encodedText = ChaoticBase90.encode(originalText);
      String decodedText = ChaoticBase90.decode(encodedText);

      Assertions.assertEquals(originalText, decodedText);
    }
  }

  public static String generateRandomChinese(int length) {
    StringBuilder stringBuilder = new StringBuilder();

    for (int i = 0; i < length; i++) {
      char randomChar = generateRandomChineseChar();
      stringBuilder.append(randomChar);
    }

    return stringBuilder.toString();
  }

  public static char generateRandomChineseChar() {
    Random random = new Random();
    int minValue = 0x4E00; // 中文字符的最小 Unicode 编码
    int maxValue = 0x9FFF; // 中文字符的最大 Unicode 编码
    int randomValue = minValue + random.nextInt(maxValue - minValue + 1);
    return (char) randomValue;
  }
}

