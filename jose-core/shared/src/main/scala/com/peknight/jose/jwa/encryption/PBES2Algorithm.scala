package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.jose.jwa.encryption.HeaderParam.{p2c, p2s}
import com.peknight.security.cipher.{AESWrap, CipherAlgorithm}
import com.peknight.security.digest.Digest
import com.peknight.security.mac.HmacSHA2
import com.peknight.security.pbe.PBEWithPRFAndEncryption

trait PBES2Algorithm extends KeyEncryptionAlgorithm with PBEWithPRFAndEncryption:
  def prf: HmacSHA2
  def encryption: AESWrap
  def headerParams: Seq[HeaderParam] = Seq(p2s, p2c)
  def requirement: Requirement = Optional
  override def algorithm: String = s"PBES2-HS${prf.digest.bitLength}+A${encryption.blockSize * 8}KW"
end PBES2Algorithm
