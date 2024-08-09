@file:Suppress("DuplicatedCode", "unused")

package cn.labzen.algorithm.crypto.checksum

/**
 * CRC-16 循环冗余校验
 *
 * - CRC16_CCITT：多项式x16+x12+x5+1（0x1021），初始值0x0000，低位在前，高位在后，结果与0x0000异或
 * - CRC16_CCITT_FALSE：多项式x16+x12+x5+1（0x1021），初始值0xFFFF，低位在后，高位在前，结果与0x0000异或
 * - CRC16_XMODEM：多项式x16+x12+x5+1（0x1021），初始值0x0000，低位在后，高位在前，结果与0x0000异或
 * - CRC16_X25：多项式x16+x12+x5+1（0x1021），初始值0xffff，低位在前，高位在后，结果与0xFFFF异或
 * - CRC16_MODBUS：多项式x16+x15+x2+1（0x8005），初始值0xFFFF，低位在前，高位在后，结果与0x0000异或
 * - CRC16_IBM：多项式x16+x15+x2+1（0x8005），初始值0x0000，低位在前，高位在后，结果与0x0000异或
 * - CRC16_MAXIM：多项式x16+x15+x2+1（0x8005），初始值0x0000，低位在前，高位在后，结果与0xFFFF异或
 * - CRC16_USB：多项式x16+x15+x2+1（0x8005），初始值0xFFFF，低位在前，高位在后，结果与0xFFFF异或
 * - CRC16_DNP：多项式x16+x13+x12+x11+x10+x8+x6+x5+x2+1（0x3D65），初始值0x0000，低位在前，高位在后，结果与0xFFFF异或
 *
 * 1. 预置1个16位的寄存器为十六进制FFFF（即全为1），称此寄存器为CRC寄存器；
 * 1. 把第一个8位二进制数据（既通讯信息帧的第一个字节）与16位的CRC寄存器的低8位相异或，把结果放于CRC寄存器，高八位数据不变；
 * 1. 把CRC寄存器的内容右移一位（朝低位）用0填补最高位，并检查右移后的移出位；
 * 1. 如果移出位为0：重复第3步（再次右移一位）；如果移出位为1，CRC寄存器与多项式A001（1010 0000 0000 0001）进行异或；
 * 1. 重复步骤3和4，直到右移8次，这样整个8位数据全部进行了处理；
 * 1. 重复步骤2到步骤5，进行通讯信息帧下一个字节的处理；
 * 1. 将该通讯信息帧所有字节按上述步骤计算完成后，得到的16位CRC寄存器的高、低字节进行交换；
 * 1. 最后得到的CRC寄存器内容即为：CRC码。
 *
 * 以上计算步骤中的多项式0xA001是0x8005按位颠倒后的结果。0x8408是0x1021按位颠倒后的结果。
 *
 * 在线校验工具
 * - http://www.ip33.com/crc.html
 * - https://blog.csdn.net/htmlxx/article/details/17369105
 *
 * @author [Dean Zhao](mailto:rcarlosdasilva@qq.com)
 */
object Crc16 {

  private const val VALUE_00 = 0x0000
  private const val VALUE_01 = 0x0001
  private const val VALUE_0F = 0x00ff
  private const val VALUE_FF = 0xffff
  private const val POLY_8408 = 0x8408
  private const val POLY_1021 = 0x1021
  private const val POLY_A001 = 0xa001
  private const val POLY_A6BC = 0xa6bc

  /**
   * CRC16_CCITT：多项式x16+x12+x5+1（0x1021），初始值0x0000，低位在前，高位在后，结果与0x0000异或
   * 0x8408是0x1021按位颠倒后的结果。
   */
  fun ccitt(buffer: ByteArray): Int {
    var wCRCin = VALUE_00
    for (b in buffer) {
      wCRCin = wCRCin xor (b.toInt() and VALUE_0F)
      for (j in 0..7) {
        if (wCRCin and VALUE_01 != 0) {
          wCRCin = wCRCin shr 1
          wCRCin = wCRCin xor POLY_8408
        } else {
          wCRCin = wCRCin shr 1
        }
      }
    }
    return VALUE_00.let { wCRCin = wCRCin xor it; wCRCin }
  }

  /**
   * CRC-CCITT (0xFFFF)
   * CRC16_CCITT_FALSE：多项式x16+x12+x5+1（0x1021），初始值0xFFFF，低位在后，高位在前，结果与0x0000异或
   */
  fun ccittWithFalse(buffer: ByteArray): Int {
    var wCRCin = VALUE_FF
    for (b in buffer) {
      for (i in 0..7) {
        val bit = b.toInt() shr 7 - i and 1 == 1
        val c15 = wCRCin shr 15 and 1 == 1
        wCRCin = wCRCin shl 1
        if (c15 xor bit) {
          wCRCin = wCRCin xor POLY_1021
        }
      }
    }
    wCRCin = wCRCin and VALUE_FF
    return VALUE_00.let { wCRCin = wCRCin xor it; wCRCin }
  }


  /**
   * CRC-CCITT (XModem)
   * CRC16_XMODEM：多项式x16+x12+x5+1（0x1021），初始值0x0000，低位在后，高位在前，结果与0x0000异或
   */
  fun xmodem(buffer: ByteArray): Int {
    var wCRCin = VALUE_00
    for (b in buffer) {
      for (i in 0..7) {
        val bit = b.toInt() shr 7 - i and 1 == 1
        val c15 = wCRCin shr 15 and 1 == 1
        wCRCin = wCRCin shl 1
        if (c15 xor bit) {
          wCRCin = wCRCin xor POLY_1021
        }
      }
    }
    wCRCin = wCRCin and VALUE_FF
    return VALUE_00.let { wCRCin = wCRCin xor it; wCRCin }
  }

  /**
   * CRC16_X25：多项式x16+x12+x5+1（0x1021），初始值0xffff，低位在前，高位在后，结果与0xFFFF异或
   * 0x8408是0x1021按位颠倒后的结果。
   */
  fun x25(buffer: ByteArray): Int {
    var wCRCin = VALUE_FF
    for (b in buffer) {
      wCRCin = wCRCin xor (b.toInt() and VALUE_0F)
      for (j in 0..7) {
        if (wCRCin and VALUE_01 != 0) {
          wCRCin = wCRCin shr 1
          wCRCin = wCRCin xor POLY_8408
        } else {
          wCRCin = wCRCin shr 1
        }
      }
    }
    return VALUE_FF.let { wCRCin = wCRCin xor it; wCRCin }
  }

  /**
   * CRC-16 (Modbus)
   * CRC16_MODBUS：多项式x16+x15+x2+1（0x8005），初始值0xFFFF，低位在前，高位在后，结果与0x0000异或
   * 0xA001是0x8005按位颠倒后的结果
   */
  fun modbus(buffer: ByteArray): Int {
    var wCRCin = VALUE_FF
    for (b in buffer) {
      wCRCin = wCRCin xor (b.toInt() and VALUE_0F)
      for (j in 0..7) {
        if (wCRCin and VALUE_01 != 0) {
          wCRCin = wCRCin shr 1
          wCRCin = wCRCin xor POLY_A001
        } else {
          wCRCin = wCRCin shr 1
        }
      }
    }
    return VALUE_00.let { wCRCin = wCRCin xor it; wCRCin }
  }

  /**
   * CRC-16
   * CRC16_IBM：多项式x16+x15+x2+1（0x8005），初始值0x0000，低位在前，高位在后，结果与0x0000异或
   * 0xA001是0x8005按位颠倒后的结果
   */
  fun ibm(buffer: ByteArray): Int {
    var wCRCin = VALUE_00
    for (b in buffer) {
      wCRCin = wCRCin xor (b.toInt() and VALUE_0F)
      for (j in 0..7) {
        if (wCRCin and VALUE_01 != 0) {
          wCRCin = wCRCin shr 1
          wCRCin = wCRCin xor POLY_A001
        } else {
          wCRCin = wCRCin shr 1
        }
      }
    }
    return VALUE_00.let { wCRCin = wCRCin xor it; wCRCin }
  }

  /**
   * CRC16_MAXIM：多项式x16+x15+x2+1（0x8005），初始值0x0000，低位在前，高位在后，结果与0xFFFF异或
   * 0xA001是0x8005按位颠倒后的结果
   */
  fun maxim(buffer: ByteArray): Int {
    var wCRCin = VALUE_00
    for (b in buffer) {
      wCRCin = wCRCin xor (b.toInt() and VALUE_0F)
      for (j in 0..7) {
        if (wCRCin and VALUE_01 != 0) {
          wCRCin = wCRCin shr 1
          wCRCin = wCRCin xor POLY_A001
        } else {
          wCRCin = wCRCin shr 1
        }
      }
    }
    return VALUE_FF.let { wCRCin = wCRCin xor it; wCRCin }
  }

  /**
   * CRC16_USB：多项式x16+x15+x2+1（0x8005），初始值0xFFFF，低位在前，高位在后，结果与0xFFFF异或
   * 0xA001是0x8005按位颠倒后的结果
   */
  fun usb(buffer: ByteArray): Int {
    var wCRCin = VALUE_FF
    for (b in buffer) {
      wCRCin = wCRCin xor (b.toInt() and VALUE_0F)
      for (j in 0..7) {
        if (wCRCin and VALUE_01 != 0) {
          wCRCin = wCRCin shr 1
          wCRCin = wCRCin xor POLY_A001
        } else {
          wCRCin = wCRCin shr 1
        }
      }
    }
    return 0xffff.let { wCRCin = wCRCin xor it; wCRCin }
  }

  /**
   * CRC16_DNP：多项式x16+x13+x12+x11+x10+x8+x6+x5+x2+1（0x3D65），初始值0x0000，低位在前，高位在后，结果与0xFFFF异或
   * 0xA6BC是0x3D65按位颠倒后的结果
   */
  fun dnp(buffer: ByteArray): Int {
    var wCRCin = VALUE_00
    for (b in buffer) {
      wCRCin = wCRCin xor (b.toInt() and VALUE_0F)
      for (j in 0..7) {
        if (wCRCin and VALUE_01 != 0) {
          wCRCin = wCRCin shr 1
          wCRCin = wCRCin xor POLY_A6BC
        } else {
          wCRCin = wCRCin shr 1
        }
      }
    }
    return 0xffff.let { wCRCin = wCRCin xor it; wCRCin }
  }
}
