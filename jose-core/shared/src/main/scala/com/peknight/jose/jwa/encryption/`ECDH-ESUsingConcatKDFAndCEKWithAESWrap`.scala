package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.AESWrap

trait `ECDH-ESUsingConcatKDFAndCEKWithAESWrap` extends `ECDH-ESAlgorithm`:
  def encryption: AESWrap
  override def algorithm: String = s"ECDH-ES+A${encryption.blockSize * 8}KW"
end `ECDH-ESUsingConcatKDFAndCEKWithAESWrap`
