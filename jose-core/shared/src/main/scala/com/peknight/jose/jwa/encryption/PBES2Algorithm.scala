package com.peknight.jose.jwa.encryption

import com.peknight.jose.jwa.encryption.HeaderParam.{p2c, p2s}
import com.peknight.jose.jwk.KeyType
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.cipher.Symmetric
import com.peknight.security.mac.HmacSHA2

trait PBES2Algorithm extends KeyEncryptionAlgorithm with Symmetric with PBES2AlgorithmPlatform:
  def prf: HmacSHA2
  def encryption: AESWrapAlgorithm
  def headerParams: Seq[HeaderParam] = Seq(p2s, p2c)
  def requirement: Requirement = Optional
  def keyTypes: List[KeyType] = Nil
  private[jose] def canOverrideCek: Boolean = encryption.canOverrideCek
  def algorithm: String = s"PBES2-HS${prf.digest.bitLength}+A${encryption.blockSize * 8}KW"
end PBES2Algorithm
object PBES2Algorithm:
  val values: List[PBES2Algorithm] = List(`PBES2-HS256+A128KW`, `PBES2-HS384+A192KW`, `PBES2-HS512+A256KW`)
end PBES2Algorithm
