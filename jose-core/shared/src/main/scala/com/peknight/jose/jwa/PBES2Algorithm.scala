package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.pbe.PBES2WithMACAndEncryption
import com.peknight.jose.jwa.HeaderParam.{p2c, p2s}
import com.peknight.jose.jwa.Requirement.Optional

trait PBES2Algorithm extends KeyEncryptionAlgorithm:
  val headerParams: Seq[HeaderParam] = Seq(p2s, p2c)
  val requirement: Requirement = Optional
end PBES2Algorithm
object PBES2Algorithm:
  private[this] case class PBES2Algorithm(algorithm: PBES2WithMACAndEncryption)
    extends com.peknight.jose.jwa.PBES2Algorithm
  def apply(algorithm: PBES2WithMACAndEncryption): com.peknight.jose.jwa.PBES2Algorithm = PBES2Algorithm(algorithm)
end PBES2Algorithm
