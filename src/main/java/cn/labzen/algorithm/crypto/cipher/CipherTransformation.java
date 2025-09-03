package cn.labzen.algorithm.crypto.cipher;

import javax.annotation.Nonnull;

public record CipherTransformation(CipherAlgorithm algorithm, CipherMode mode, CipherPadding padding) {

  @Nonnull
  @Override
  public String toString() {
    return algorithm.getValue() + "/" + mode.getValue() + "/" + padding.getValue();
  }
}
