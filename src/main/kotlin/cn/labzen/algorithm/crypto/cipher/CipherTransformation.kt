package cn.labzen.algorithm.crypto.cipher

data class CipherTransformation(
  val algorithm: CipherAlgorithm,
  val mode: CipherMode,
  val padding: CipherPadding
) {

  override fun toString(): String =
    "${algorithm.value}/${mode.value}/${padding.value}"
}
