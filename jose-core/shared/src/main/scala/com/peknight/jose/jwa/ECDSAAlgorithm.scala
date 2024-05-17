package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.signature.DigestWithEncryption

trait ECDSAAlgorithm extends DigitalSignatureAlgorithm
object ECDSAAlgorithm:
  private[this] case class ECDSAAlgorithm(algorithm: DigestWithEncryption, requirement: Requirement)
    extends com.peknight.jose.jwa.ECDSAAlgorithm
  def apply(algorithm: DigestWithEncryption, requirement: Requirement): com.peknight.jose.jwa.ECDSAAlgorithm =
    ECDSAAlgorithm(algorithm, requirement)
end ECDSAAlgorithm