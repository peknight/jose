package com.peknight.jose.jwa.encryption

import com.peknight.jose.Requirement
import com.peknight.jose.Requirement.Optional
import com.peknight.jose.jwa.encryption.HeaderParam.{p2c, p2s}
import com.peknight.security.cipher.AESWrap
import com.peknight.security.mac.HmacSHA2

trait PBES2Algorithm extends KeyEncryptionAlgorithm:
  def prf: HmacSHA2
  def encryption: AESWrap
  def headerParams: Seq[HeaderParam] = Seq(p2s, p2c)
  def requirement: Requirement = Optional
  def algorithm: String = s"PBES2-HS${prf.digest.bitLength}+A${encryption.blockSize * 8}KW"
end PBES2Algorithm
object PBES2Algorithm:
  val values: List[PBES2Algorithm] = List(`PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`)
end PBES2Algorithm
