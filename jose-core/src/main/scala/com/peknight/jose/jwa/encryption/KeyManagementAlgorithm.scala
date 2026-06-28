package com.peknight.jose.jwa.encryption

trait KeyManagementAlgorithm extends JWEAlgorithm with KeyManagementAlgorithmPlatform:
  private[jose] def canOverrideCek: Boolean
end KeyManagementAlgorithm
object KeyManagementAlgorithm:
  val values: List[KeyManagementAlgorithm] =
    KeyEncryptionAlgorithm.values :::
      KeyWrappingAlgorithm.values :::
      DirectEncryptionAlgorithm.values :::
      KeyAgreementAlgorithm.values
end KeyManagementAlgorithm
