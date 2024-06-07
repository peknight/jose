package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.jose.jwa.encryption.HeaderParam.{iv, tag}
import com.peknight.security.cipher.AESWrap

trait AESGCMKWAlgorithm extends KeyEncryptionAlgorithm with AESWrap:
  def headerParams: Seq[HeaderParam] = Seq(iv, tag)
  def requirement: Requirement = Optional
  override def algorithm: String = s"A${blockSize * 8}GCMKW"
end AESGCMKWAlgorithm
