package cn.labzen.algorithm.crypto;

import net.jacksum.HashFunctionFactory;
import net.jacksum.algorithms.AbstractChecksum;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;

public class DigestsTest {

  private static SimpleBean bean;

  @BeforeAll
  static void init() {
    bean = new SimpleBean("Dean", 18);
  }

  @Test
  void testBlake3() {
    Assertions.assertEquals("b3d4f8803f7e24b8f389b072e75477cdbcfbe074080fb5e500e53e26e054158e", Digests.blake3("123"));
    Assertions.assertEquals("d12efa543f91d266ab3613d88d01d47f0696735b6a84cd9e6835d09bbe5c172c",
        Digests.blake3("123", 2));
    Assertions.assertEquals("e4c8a83af83b23ccf7e3de064e1a2ee8ce9833d5bf8c597b549141ece3b7b177",
        Digests.blake3("123", 3));
    Assertions.assertEquals("f1cbdc63c8f48c34eab8d5f86637e7ddfe41bf45f76ca2a05d8f7ceebe12aeea",
        Digests.blake3("一二三", Charset.forName("GB2312"), 1));

    URL resource = this.getClass().getClassLoader().getResource("simple.txt");
    Assertions.assertNotNull(resource);
    File file = new File(resource.getFile());

    String blake3File = Digests.blake3(file);
    Assertions.assertNotNull(blake3File);

    String blake3Bean = Digests.blake3(bean);
    Assertions.assertNotNull(blake3Bean);
  }

  @Test
  void testBlake2() {
    Assertions.assertEquals("f5d67bae73b0e10d0dfd3043b3f4f100ada014c5c37bd5ce97813b13f5ab2bcf", Digests.blake2("123"));
    Assertions.assertEquals("89cade5a937b8eda754e4d6f5f874241dc2c1fbf48b18006a9787a1d2e56b2c5",
        Digests.blake2("123", 2));
    Assertions.assertEquals("f8ccec543dcc03fad83d0dcef993f03cf004257cd0e044f96490b73d1363e3a1",
        Digests.blake2("123", 3));
    Assertions.assertEquals("bf59ffc56500c23dacdd8ff90b5e6f6eca3e28aa810f69a1fd44875cb2999be1",
        Digests.blake2("一二三"));

    URL resource = this.getClass().getClassLoader().getResource("simple.txt");
    Assertions.assertNotNull(resource);
    File file = new File(resource.getFile());

    String blake2File = Digests.blake2(file);
    Assertions.assertNotNull(blake2File);

    String blake2Bean = Digests.blake2(bean);
    Assertions.assertNotNull(blake2Bean);
  }

  @Test
  void testRipemd() {
    Assertions.assertEquals("e3431a8e0adbf96fd140103dc6f63a3f8fa343ab", Digests.ripemd("123"));
    Assertions.assertEquals("011b21dfa339a2e4a9ad3ed958d72f228c4747e9", Digests.ripemd("123", 2));
    Assertions.assertEquals("e00566b22510d207d7e55e9f2645ef5a08e34642", Digests.ripemd("123", 3));
    Assertions.assertEquals("36cd2ad9ede21f708764c4b33a48558245d87f41", Digests.ripemd("一二三"));

    URL resource = this.getClass().getClassLoader().getResource("simple.txt");
    Assertions.assertNotNull(resource);
    File file = new File(resource.getFile());

    String ripemdFile = Digests.ripemd(file);
    Assertions.assertNotNull(ripemdFile);

    String ripemdBean = Digests.ripemd(bean);
    Assertions.assertNotNull(ripemdBean);
  }

  @Test
  void testSM3() {
    Assertions.assertEquals("6e0f9e14344c5406a0cf5a3b4dfb665f87f4a771a31f7edbb5c72874a32b2957", Digests.sm3("123"));
    Assertions.assertEquals("557e36c82492bc49b4428ce5b3216de99842f8290811f6410004a5c61e1269bf", Digests.sm3("123", 2));
    Assertions.assertEquals("aa4d4977a5b76304e4bd33799600df536bd193954aa6c623c6d4911c1160dd5e",
        Digests.sm3("一二三", Charset.forName("GB2312"), 1));

    URL resource = this.getClass().getClassLoader().getResource("simple.txt");
    Assertions.assertNotNull(resource);
    File file = new File(resource.getFile());

    String sm3File = Digests.sm3(file);
    Assertions.assertNotNull(sm3File);

    String sm3Bean = Digests.sm3(bean);
    Assertions.assertNotNull(sm3Bean);
  }

  @Test
  void testTiger() {
    Assertions.assertEquals("a86807bb96a714fe9b22425893e698334cd71e36b0eef2be", Digests.tiger("123"));
    Assertions.assertEquals("8cfedcdfeaf395fa52972b9d284c45d94c39b098f09bdfaa", Digests.tiger("123", 2));
    Assertions.assertEquals("cca8995a552d08370bda9c4b77b61012b5e04222e481b377",
        Digests.tiger("一二三", Charset.forName("GB2312"), 1));

    URL resource = this.getClass().getClassLoader().getResource("simple.txt");
    Assertions.assertNotNull(resource);
    File file = new File(resource.getFile());

    String tigerFile = Digests.tiger(file);
    Assertions.assertNotNull(tigerFile);

    String tigerBean = Digests.tiger(bean);
    Assertions.assertNotNull(tigerBean);
  }

  @Test
  void testWhirlpool() {
    Assertions.assertEquals(
        "344907e89b981caf221d05f597eb57a6af408f15f4dd7895bbd1b96a2938ec24a7dcf23acb94ece0b6d7b0640358bc56bdb448194b9305311aff038a834a079f",
        Digests.whirlpool("123"));
    Assertions.assertEquals(
        "85cc0b60c1e90a17854454ab2c1489edbf25a7d907f2f0caa532ea1391d53c5d2db9aa0c3a90adac304b826639f452bd9ce79ee0bc6d5e6d23b04abc3d913aea",
        Digests.whirlpool("123", 2));
    Assertions.assertEquals(
        "a88437f242b67544e8dc61de474c95168ad25b1efde185705a8907f905817347b5be4a98eedc335fa3d5091adda102343123782f82be80ddbbe887b04f0c15ae",
        Digests.whirlpool("一二三", Charset.forName("GB2312"), 1));

    URL resource = this.getClass().getClassLoader().getResource("simple.txt");
    Assertions.assertNotNull(resource);
    File file = new File(resource.getFile());

    String whirlpoolFile = Digests.whirlpool(file);
    Assertions.assertNotNull(whirlpoolFile);

    String whirlpoolBean = Digests.whirlpool(bean);
    Assertions.assertNotNull(whirlpoolBean);
  }

  @Test
  void testMd5() {
    Assertions.assertEquals("202cb962ac59075b964b07152d234b70", Digests.md5("123"));
    Assertions.assertEquals("d022646351048ac0ba397d12dfafa304", Digests.md5("123", 2));
    Assertions.assertEquals("bb232666cd0aeea80029c27e3c01582f", Digests.md5("123", 3));
    Assertions.assertEquals("a45d4af7b243e7f393fa09bed72ac73e", Digests.md5("一二三", Charset.forName("GB2312"), 1));

    URL resource = this.getClass().getClassLoader().getResource("simple.txt");
    Assertions.assertNotNull(resource);
    File file = new File(resource.getFile());

    String md5File = Digests.md5(file);
    Assertions.assertNotNull(md5File);

    String md5Bean = Digests.md5(bean);
    Assertions.assertNotNull(md5Bean);
  }

  @Test
  void testSha2() {
    Assertions.assertEquals("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", Digests.sha2("123"));
    Assertions.assertEquals("5a77d1e9612d350b3734f6282259b7ff0a3f87d62cfef5f35e91a5604c0490a3", Digests.sha2("123", 2));
    Assertions.assertEquals("3180b4071170db0ae9f666167ed379f53468463f152e3c3cfb57d1de45fd01d6", Digests.sha2("123", 3));
    Assertions.assertEquals("b6c1ae1f8d8a07426ddb13fca5124fb0b9f1f0ef1cca6730615099cf198ca8af",
        Digests.sha2("一二三", Charset.forName("GB2312"), Digests.SHALength.SHA_256, 1));

    URL resource = this.getClass().getClassLoader().getResource("simple.txt");
    Assertions.assertNotNull(resource);
    File file = new File(resource.getFile());

    String sha2File = Digests.sha2(file);
    Assertions.assertNotNull(sha2File);

    String sha2Bean = Digests.sha2(bean);
    Assertions.assertNotNull(sha2Bean);
  }

  @Test
  void testSha3() {
    Assertions.assertEquals("a03ab19b866fc585b5cb1812a2f63ca861e7e7643ee5d43fd7106b623725fd67", Digests.sha3("123"));
    Assertions.assertEquals("b2a62fbb0eb7806b184c995904977939536e3d44d4814db79b5977548508936c", Digests.sha3("123", 2));
    Assertions.assertEquals("656060b18f4eaeaa16ac7f7f404877d0511b1b7714320ef26b877b0517583e69", Digests.sha3("123", 3));
    Assertions.assertEquals("e9ae7204b9ba43586c74c22cd6d5f904ac06071da791cc6ffb283329a830a9d3", Digests.sha3("一二三"));

    URL resource = this.getClass().getClassLoader().getResource("simple.txt");
    Assertions.assertNotNull(resource);
    File file = new File(resource.getFile());

    String sha3File = Digests.sha3(file);
    Assertions.assertNotNull(sha3File);

    String sha3Bean = Digests.sha3(bean);
    Assertions.assertNotNull(sha3Bean);
  }

  public static void main(String[] args) throws NoSuchAlgorithmException {
    AbstractChecksum crc32 = HashFunctionFactory.getHashFunction("adler32");
    crc32.update("d952f164".getBytes());
    long value = crc32.getValue();
    System.out.println(Long.toHexString(value));

    AbstractChecksum crc322 = HashFunctionFactory.getHashFunction("cksum");
    crc322.update("d952f164".getBytes());
    long value2 = crc322.getValue();
    System.out.println(Long.toHexString(value2));

    AbstractChecksum crc323 = HashFunctionFactory.getHashFunction("crc64");
    crc323.update("d952f164".getBytes());
    long value3 = crc323.getValue();
    System.out.println(Long.toHexString(value3));

    AbstractChecksum crc324 = HashFunctionFactory.getHashFunction("elf");
    crc324.update("d952f164".getBytes());
    long value4 = crc324.getValue();
    System.out.println(Long.toHexString(value4));
  }
}
