package cn.labzen.algorithm.crypto.cipher

import cn.labzen.tool.util.Bytes
import java.security.AlgorithmParameters
import java.security.Key
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class SymmetricalCipher internal constructor(private val cipherTransformation: CipherTransformation) {

  private lateinit var key: Key
  private var parameter: AlgorithmParameters? = null
  private lateinit var encryptor: Cipher
  private lateinit var decryptor: Cipher

  @JvmOverloads
  fun randomKey(algorithm: KeyGeneratorAlgorithm? = null, size: Int? = null): SymmetricalCipher {
    val a = algorithm ?: DEFAULT_KEY_GENERATOR_ALGORITHM
    val s = size ?: when (a) {
      KeyGeneratorAlgorithm.AES -> 128
      KeyGeneratorAlgorithm.DES -> 56
      KeyGeneratorAlgorithm.DESEDE -> 168
      else -> null
    }

    val kg = keyGenerators.computeIfAbsent("$a:$s") {
      KeyGenerator.getInstance(a.value).apply {
        if (s != null) {
          init(s)
        }
      }
    }

    this.key = kg.generateKey()
    return this
  }

  @JvmOverloads
  fun withKey(value: String, algorithm: CipherAlgorithm? = null): SymmetricalCipher =
    withKey(value.toByteArray(), algorithm)

  @JvmOverloads
  fun withKey(value: ByteArray, algorithm: CipherAlgorithm? = null): SymmetricalCipher {
    key = SecretKeySpec(value, algorithm?.value ?: DEFAULT_CIPHER_ALGORITHM.value)
    return this
  }

  fun withKey(value: Key): SymmetricalCipher {
    this.key = value
    return this
  }

  fun keyBytes(): ByteArray? =
    if (this::key.isInitialized) {
      key.encoded
    } else null

  fun keyString(): String =
    Bytes.bytesToHexString(key.encoded)

  fun withParameter(parameter: AlgorithmParameterSpec): SymmetricalCipher {
    this.parameter = AlgorithmParameters.getInstance(cipherTransformation.algorithm.value).apply {
      init(parameter)
    }
    return this
  }

  fun withIVParameter(bytes: ByteArray): SymmetricalCipher {
    return withParameter(IvParameterSpec(bytes))
  }

  @Synchronized
  fun encrypt(plaintext: String): ByteArray =
    encrypt(plaintext.toByteArray())

  @Synchronized
  fun encrypt(bytes: ByteArray): ByteArray {
    if (!this::encryptor.isInitialized) {
      encryptor = createCipherInstance(Cipher.ENCRYPT_MODE)
    }

    return encryptor.doFinal(bytes)
  }

  @Synchronized
  fun decrypt(bytes: ByteArray): ByteArray {
    if (!this::decryptor.isInitialized) {
      decryptor = createCipherInstance(Cipher.DECRYPT_MODE)
    }

    return decryptor.doFinal(bytes)
  }

  private fun createCipherInstance(mode: Int) =
    Cipher.getInstance(cipherTransformation.toString()).apply {
      if (parameter != null) {
        init(mode, key, parameter)
      } else {
        init(mode, key)
      }
    }

  companion object {
    private val DEFAULT_KEY_GENERATOR_ALGORITHM = KeyGeneratorAlgorithm.AES
    private val DEFAULT_CIPHER_ALGORITHM = CipherAlgorithm.AES

    private val keyGenerators = mutableMapOf<String, KeyGenerator>()
  }
}
