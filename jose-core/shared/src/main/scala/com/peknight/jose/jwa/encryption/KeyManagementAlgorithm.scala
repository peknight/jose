package com.peknight.jose.jwa.encryption

trait KeyManagementAlgorithm extends JWEAlgorithm
object KeyManagementAlgorithm:
  val values: List[KeyManagementAlgorithm] =
    KeyEncryptionAlgorithm.values :::
      KeyWrappingAlgorithm.values :::
      DirectEncryptionAlgorithm.values :::
      KeyAgreementAlgorithm.values
end KeyManagementAlgorithm
