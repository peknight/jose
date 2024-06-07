package com.peknight.jose.jwa.encryption

import com.peknight.security.cipher.AESWrap

trait AESWrapAlgorithm extends KeyWrappingAlgorithm with AESWrap:
  def headerParams: Seq[HeaderParam] = Seq.empty
  override def algorithm: String = s"A${blockSize * 8}KW"
end AESWrapAlgorithm
