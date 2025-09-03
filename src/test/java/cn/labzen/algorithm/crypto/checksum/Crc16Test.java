package cn.labzen.algorithm.crypto.checksum;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Crc16Test {

  private static final byte[] TEST_DATA = "123456789".getBytes();

  @Test
  void testCcitt() {
    // CRC-16/CCITT (0xFFFF) 的 "123456789" 结果是 0x29B1
    int result = Crc16.ccitt(TEST_DATA);
    assertEquals(0x2189, result & 0xFFFF);
  }

  @Test
  void testCcittFalse() {
    // CRC-16/CCITT-FALSE 的 "123456789" 结果是 0x29B1
    int result = Crc16.ccittWithFalse(TEST_DATA);
    assertEquals(0x29B1, result & 0xFFFF);
  }

  @Test
  void testXmodem() {
    // CRC-16/XMODEM 的 "123456789" 结果是 0x31C3
    int result = Crc16.xmodem(TEST_DATA);
    assertEquals(0x31C3, result & 0xFFFF);
  }

  @Test
  void testX25() {
    // CRC-16/X25 的 "123456789" 结果是 0x906E
    int result = Crc16.x25(TEST_DATA);
    assertEquals(0x906E, result & 0xFFFF);
  }

  @Test
  void testModbus() {
    // CRC-16/MODBUS 的 "123456789" 结果是 0x4B37
    int result = Crc16.modbus(TEST_DATA);
    assertEquals(0x4B37, result & 0xFFFF);
  }

  @Test
  void testIbm() {
    // CRC-16/IBM (又叫 CRC-16/ARC) 的 "123456789" 结果是 0xBB3D
    int result = Crc16.ibm(TEST_DATA);
    assertEquals(0xBB3D, result & 0xFFFF);
  }

  @Test
  void testMaxim() {
    // CRC-16/MAXIM 的 "123456789" 结果是 0x44C2
    int result = Crc16.maxim(TEST_DATA);
    assertEquals(0x44C2, result & 0xFFFF);
  }

  @Test
  void testUsb() {
    // CRC-16/USB 的 "123456789" 结果是 0xB4C8
    int result = Crc16.usb(TEST_DATA);
    assertEquals(0xB4C8, result & 0xFFFF);
  }

  @Test
  void testDnp() {
    // CRC-16/DNP 的 "123456789" 结果是 0xEA82
    int result = Crc16.dnp(TEST_DATA);
    assertEquals(0xEA82, result & 0xFFFF);
  }
}
