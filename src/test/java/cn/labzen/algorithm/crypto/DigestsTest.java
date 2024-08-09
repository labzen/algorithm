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
    Assertions.assertEquals("d287bfcd33a66d276e8f87583a3db152f8d618d21811635cc0e26e27b8b71603",
        Digests.blake3("123", 2));
    Assertions.assertEquals("21ff34cb269b437a99b068fe18043ab064379c12fad54487cb2c113b35f4da47",
        Digests.blake3("123", 3));
    Assertions.assertEquals("f1cbdc63c8f48c34eab8d5f86637e7ddfe41bf45f76ca2a05d8f7ceebe12aeea",
        Digests.blake3("一二三", Charset.forName("GB2312")));

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
    Assertions.assertEquals("8cd9f28e4a90b82fbe33b54beae4e1e311abd9900a242ac53edce5546def5c73",
        Digests.blake2("123", 2));
    Assertions.assertEquals("650cac46111e38ed8265017653adecb9eeed04ac5dc940b91d27e1a8bb0910dc",
        Digests.blake2("123", 3));
    Assertions.assertEquals("bf59ffc56500c23dacdd8ff90b5e6f6eca3e28aa810f69a1fd44875cb2999be1", Digests.blake2("一二三"));

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
    Assertions.assertEquals("6d159064338d946193df43096757e14c97d80956", Digests.ripemd("123", 2));
    Assertions.assertEquals("faba18244a6813748036a822849862d24fa1377b", Digests.ripemd("123", 3));
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
    Assertions.assertEquals("56a0036b75b29f4d3877199a60060d430f23f899fce4d65733c7609a885a292a", Digests.sm3("123", 2));
    Assertions.assertEquals("aa4d4977a5b76304e4bd33799600df536bd193954aa6c623c6d4911c1160dd5e",
        Digests.sm3("一二三", Charset.forName("GB2312")));

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
    Assertions.assertEquals("d65b534877032ffd3bdf0dff87ff0dc5f339ba719725451c", Digests.tiger("123", 2));
    Assertions.assertEquals("cca8995a552d08370bda9c4b77b61012b5e04222e481b377",
        Digests.tiger("一二三", Charset.forName("GB2312")));

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
        "6e71ff4c23fc886980c4def732ac95c90ac3b0ed58d8a41187fd7adde87182ec219cf131274f38dbde7233645eb32f19bf5ae66c5d30f3b12d01ca507dfa5fd7",
        Digests.whirlpool("123", 2));
    Assertions.assertEquals(
        "a88437f242b67544e8dc61de474c95168ad25b1efde185705a8907f905817347b5be4a98eedc335fa3d5091adda102343123782f82be80ddbbe887b04f0c15ae",
        Digests.whirlpool("一二三", Charset.forName("GB2312")));

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
    Assertions.assertEquals("d9b1d7db4cd6e70935368a1efb10e377", Digests.md5("123", 2));
    Assertions.assertEquals("7363a0d0604902af7b70b271a0b96480", Digests.md5("123", 3));
    Assertions.assertEquals("a45d4af7b243e7f393fa09bed72ac73e", Digests.md5("一二三", Charset.forName("GB2312")));

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
    Assertions.assertEquals("173af653133d964edfc16cafe0aba33c8f500a07f3ba3f81943916910c257705", Digests.sha2("123", 2));
    Assertions.assertEquals("1f707cd9f1548819257c8f0b432af46955e4e351a7a61236388eb5bd27cdba7c", Digests.sha2("123", 3));
    Assertions.assertEquals("b6c1ae1f8d8a07426ddb13fca5124fb0b9f1f0ef1cca6730615099cf198ca8af",
        Digests.sha2("一二三", Charset.forName("GB2312")));

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
    Assertions.assertEquals("eda803a4c51769b565aca0aab1b326c0d8cd9730181d4ae407c6784225b44c94", Digests.sha3("123", 2));
    Assertions.assertEquals("c5246e48c5486b51bce49db970a9df0f779beb00f9e533994198702a6174e639", Digests.sha3("123", 3));
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
