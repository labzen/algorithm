package cn.labzen.algorithm.crypto

import cn.labzen.algorithm.crypto.cipher.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

object Ciphers {

  private val BC_PROVIDER = BouncyCastleProvider()

  private val DEFAULT_SYMMETRICAL_TRANSFORMATION = CipherTransformation(
    CipherAlgorithm.AES,
    CipherMode.CBC,
    CipherPadding.PKCS5_PADDING
  )

  init {
    Security.addProvider(BC_PROVIDER)
  }

  @JvmStatic
  @JvmOverloads
  fun symmetrical(cipherTransformation: CipherTransformation? = null): SymmetricalCipher =
    SymmetricalCipher(cipherTransformation ?: DEFAULT_SYMMETRICAL_TRANSFORMATION)

  @JvmStatic
  fun symmetrical(algorithm: CipherAlgorithm, mode: CipherMode, padding: CipherPadding) =
    symmetrical(CipherTransformation(algorithm, mode, padding))

}
