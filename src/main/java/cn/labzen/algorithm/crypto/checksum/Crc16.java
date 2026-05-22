package cn.labzen.algorithm.crypto.checksum;

/**
 * CRC-16 循环冗余校验
 * <li>CRC16_CCITT：多项式x16+x12+x5+1（0x1021），初始值0x0000，低位在前，高位在后，结果与0x0000异或
 * <li>CRC16_CCITT_FALSE：多项式x16+x12+x5+1（0x1021），初始值0xFFFF，低位在后，高位在前，结果与0x0000异或
 * <li>CRC16_XMODEM：多项式x16+x12+x5+1（0x1021），初始值0x0000，低位在后，高位在前，结果与0x0000异或
 * <li>CRC16_X25：多项式x16+x12+x5+1（0x1021），初始值0xffff，低位在前，高位在后，结果与0xFFFF异或
 * <li>CRC16_MODBUS：多项式x16+x15+x2+1（0x8005），初始值0xFFFF，低位在前，高位在后，结果与0x0000异或
 * <li>CRC16_IBM：多项式x16+x15+x2+1（0x8005），初始值0x0000，低位在前，高位在后，结果与0x0000异或
 * <li>CRC16_MAXIM：多项式x16+x15+x2+1（0x8005），初始值0x0000，低位在前，高位在后，结果与0xFFFF异或
 * <li>CRC16_USB：多项式x16+x15+x2+1（0x8005），初始值0xFFFF，低位在前，高位在后，结果与0xFFFF异或
 * <li>CRC16_DNP：多项式x16+x13+x12+x11+x10+x8+x6+x5+x2+1（0x3D65），初始值0x0000，低位在前，高位在后，结果与0xFFFF异或
 * <hr/>
 * 在线校验工具:
 * <li><a href="http://www.ip33.com/crc.html">http://www.ip33.com/crc.html</a>
 * <li><a href="https://blog.csdn.net/htmlxx/article/details/17369105">https://blog.csdn.net/htmlxx/article/details/17369105</a>
 *
 * @author Dean Zhao
 */
@SuppressWarnings("DuplicatedCode")
public final class Crc16 {

  private static final int VALUE_00 = 0x0000;
  private static final int VALUE_01 = 0x0001;
  private static final int VALUE_FF = 0x00ff;
  private static final int VALUE_FFFF = 0xffff;
  private static final int POLY_8408 = 0x8408;
  private static final int POLY_1021 = 0x1021;
  private static final int POLY_A001 = 0xa001;
  private static final int POLY_A6BC = 0xa6bc;

  private Crc16() {
  }

  /**
   * CRC16_CCITT：多项式x16+x12+x5+1（0x1021），初始值0x0000，低位在前，高位在后，结果与0x0000异或
   * 0x8408是0x1021按位颠倒后的结果。
   */
  public static int ccitt(byte[] buffer) {
    int wCRCin = VALUE_00;
    for (byte b : buffer) {
      wCRCin ^= (b &  0xFF);
      for (int j = 0; j < 8; j++) {
        if ((wCRCin & VALUE_01) != 0) {
          wCRCin >>>= 1;
          wCRCin ^= POLY_8408;
        } else {
          wCRCin >>>= 1;
        }
      }
    }
    return wCRCin ^ VALUE_00;
  }

  /**
   * CRC-CCITT (0xFFFF)
   * CRC16_CCITT_FALSE：多项式x16+x12+x5+1（0x1021），初始值0xFFFF，低位在后，高位在前，结果与0x0000异或
   */
  public static int ccittWithFalse(byte[] buffer) {
    int wCRCin = VALUE_FFFF;
    for (byte b : buffer) {
      for (int i = 0; i < 8; i++) {
        boolean bit = ((b >> (7 - i)) & 1) == 1;
        boolean c15 = ((wCRCin >> 15) & 1) == 1;
        wCRCin <<= 1;
        if (c15 ^ bit) {
          wCRCin ^= POLY_1021;
        }
      }
    }
    wCRCin &= VALUE_FFFF;
    return wCRCin ^ VALUE_00;
  }

  /**
   * CRC-CCITT (XModem)
   * CRC16_XMODEM：多项式x16+x12+x5+1（0x1021），初始值0x0000，低位在后，高位在前，结果与0x0000异或
   */
  public static int xmodem(byte[] buffer) {
    int wCRCin = VALUE_00;
    for (byte b : buffer) {
      for (int i = 0; i < 8; i++) {
        boolean bit = ((b >> (7 - i)) & 1) == 1;
        boolean c15 = ((wCRCin >> 15) & 1) == 1;
        wCRCin <<= 1;
        if (c15 ^ bit) {
          wCRCin ^= POLY_1021;
        }
      }
    }
    wCRCin &= VALUE_FFFF;
    return wCRCin ^ VALUE_00;
  }

  /**
   * CRC16_X25：多项式x16+x12+x5+1（0x1021），初始值0xffff，低位在前，高位在后，结果与0xFFFF异或
   * 0x8408是0x1021按位颠倒后的结果。
   */
  public static int x25(byte[] buffer) {
    int wCRCin = VALUE_FFFF;
    for (byte b : buffer) {
      wCRCin ^= (b & VALUE_FF);
      for (int j = 0; j < 8; j++) {
        if ((wCRCin & VALUE_01) != 0) {
          wCRCin >>>= 1;
          wCRCin ^= POLY_8408;
        } else {
          wCRCin >>>= 1;
        }
      }
    }
    return wCRCin ^ VALUE_FFFF;
  }

  /**
   * CRC-16 (Modbus)
   * CRC16_MODBUS：多项式x16+x15+x2+1（0x8005），初始值0xFFFF，低位在前，高位在后，结果与0x0000异或
   * 0xA001是0x8005按位颠倒后的结果
   */
  public static int modbus(byte[] buffer) {
    int wCRCin = VALUE_FFFF;
    for (byte b : buffer) {
      wCRCin ^= (b & VALUE_FF);
      for (int j = 0; j < 8; j++) {
        if ((wCRCin & VALUE_01) != 0) {
          wCRCin >>>= 1;
          wCRCin ^= POLY_A001;
        } else {
          wCRCin >>>= 1;
        }
      }
    }
    return wCRCin ^ VALUE_00;
  }

  /**
   * CRC-16
   * CRC16_IBM：多项式x16+x15+x2+1（0x8005），初始值0x0000，低位在前，高位在后，结果与0x0000异或
   * 0xA001是0x8005按位颠倒后的结果
   */
  public static int ibm(byte[] buffer) {
    int wCRCin = VALUE_00;
    for (byte b : buffer) {
      wCRCin ^= (b & VALUE_FF);
      for (int j = 0; j < 8; j++) {
        if ((wCRCin & VALUE_01) != 0) {
          wCRCin >>>= 1;
          wCRCin ^= POLY_A001;
        } else {
          wCRCin >>>= 1;
        }
      }
    }
    return wCRCin ^ VALUE_00;
  }

  /**
   * CRC16_MAXIM：多项式x16+x15+x2+1（0x8005），初始值0x0000，低位在前，高位在后，结果与0xFFFF异或
   * 0xA001是0x8005按位颠倒后的结果
   */
  public static int maxim(byte[] buffer) {
    int wCRCin = VALUE_00;
    for (byte b : buffer) {
      wCRCin ^= (b & VALUE_FF);
      for (int j = 0; j < 8; j++) {
        if ((wCRCin & VALUE_01) != 0) {
          wCRCin >>>= 1;
          wCRCin ^= POLY_A001;
        } else {
          wCRCin >>>= 1;
        }
      }
    }
    return wCRCin ^ VALUE_FFFF;
  }

  /**
   * CRC16_USB：多项式x16+x15+x2+1（0x8005），初始值0xFFFF，低位在前，高位在后，结果与0xFFFF异或
   * 0xA001是0x8005按位颠倒后的结果
   */
  public static int usb(byte[] buffer) {
    int wCRCin = VALUE_FFFF;
    for (byte b : buffer) {
      wCRCin ^= (b & VALUE_FF);
      for (int j = 0; j < 8; j++) {
        if ((wCRCin & VALUE_01) != 0) {
          wCRCin >>>= 1;
          wCRCin ^= POLY_A001;
        } else {
          wCRCin >>>= 1;
        }
      }
    }
    return wCRCin ^ VALUE_FFFF;
  }

  /**
   * CRC16_DNP：多项式x16+x13+x12+x11+x10+x8+x6+x5+x2+1（0x3D65），初始值0x0000，低位在前，高位在后，结果与0xFFFF异或
   * 0xA6BC是0x3D65按位颠倒后的结果
   */
  public static int dnp(byte[] buffer) {
    int wCRCin = VALUE_00;
    for (byte b : buffer) {
      wCRCin ^= (b & VALUE_FF);
      for (int j = 0; j < 8; j++) {
        if ((wCRCin & VALUE_01) != 0) {
          wCRCin >>>= 1;
          wCRCin ^= POLY_A6BC;
        } else {
          wCRCin >>>= 1;
        }
      }
    }
    return wCRCin ^ VALUE_FFFF;
  }
}
