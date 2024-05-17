package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.signature.DigestWithEncryption

trait RSAAlgorithm extends DigitalSignatureAlgorithm
object RSAAlgorithm:
  private[this] case class RSAAlgorithm(algorithm: DigestWithEncryption, requirement: Requirement)
    extends com.peknight.jose.jwa.RSAAlgorithm
  def apply(algorithm: DigestWithEncryption, requirement: Requirement): com.peknight.jose.jwa.RSAAlgorithm =
    RSAAlgorithm(algorithm, requirement)
end RSAAlgorithm
