package cn.labzen.algorithm.crypto;

import cn.labzen.algorithm.crypto.Checksums.Algorithms;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URL;

public class ChecksumsTest {

  private static SimpleBean bean;

  @BeforeAll
  static void init() {
    bean = new SimpleBean("Dean", 18);
  }

  /**
   * 在线校验计算：http://www.metools.info/code/c48.html
   */
  @Test
  void testSomeAlgorithms() {
    String text = "123456";

    Assertions.assertEquals(70123830L, Checksums.string(text, Algorithms.ADLER32));
    Assertions.assertEquals(2743226970L, Checksums.string(text, Algorithms.CKSUM));

    Assertions.assertEquals(253L, Checksums.string(text, Algorithms.CRC8));
    Assertions.assertEquals(10724L, Checksums.string(text, Algorithms.CRC16));
    Assertions.assertEquals(158520161L, Checksums.string(text, Algorithms.CRC32));
    Assertions.assertEquals(3639635087L, Checksums.string(text, Algorithms.CRC32_MPEG2));
    Assertions.assertEquals(2921248394624937984L, Checksums.string(text, Algorithms.CRC64));
    Assertions.assertEquals(4708065081048288015L, Checksums.string(text, Algorithms.CRC64_ECMA));

    Assertions.assertEquals(54880134L, Checksums.string(text, Algorithms.ELF));
    Assertions.assertEquals(58994L, Checksums.string(text, Algorithms.FCS16));
    Assertions.assertEquals(11318L, Checksums.string(text, Algorithms.FLETCHER16));
    Assertions.assertEquals(-285723711L, Checksums.string(text, Algorithms.JOAAT32));

    Assertions.assertEquals(309L, Checksums.string(text, Algorithms.SUM32));
    Assertions.assertEquals(309L, Checksums.string(text, Algorithms.SUM48));
    Assertions.assertEquals(309L, Checksums.string(text, Algorithms.SUM56));
    Assertions.assertEquals(34920L, Checksums.string(text, Algorithms.SUMBSD));
    Assertions.assertEquals(7L, Checksums.string(text, Algorithms.XOR8));

    URL resource = this.getClass().getClassLoader().getResource("simple.txt");
    Assertions.assertNotNull(resource);
    File file = new File(resource.getFile());

    Long adler32File = Checksums.file(file, Algorithms.ADLER32);
    Assertions.assertNotNull(adler32File);

    Long adler32Bean = Checksums.any(bean, Algorithms.ADLER32);
    Assertions.assertNotNull(adler32Bean);
  }
}
