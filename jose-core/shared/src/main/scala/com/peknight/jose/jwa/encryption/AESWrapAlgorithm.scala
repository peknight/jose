package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.AESWrap

trait AESWrapAlgorithm extends KeyWrappingAlgorithm:
  def encryption: AESWrap
  def headerParams: Seq[HeaderParam] = Seq.empty
  def algorithm: String = s"A${encryption.blockSize * 8}KW"
end AESWrapAlgorithm
