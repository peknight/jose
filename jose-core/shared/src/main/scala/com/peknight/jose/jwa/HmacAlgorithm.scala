package com.peknight.jose.jwa

import com.peknight.crypto.algorithm.mac.Hmac

trait HmacAlgorithm extends JWSAlgorithm
object HmacAlgorithm:
  private[this] case class HmacAlgorithm(algorithm: Hmac, requirement: Requirement)
    extends com.peknight.jose.jwa.HmacAlgorithm
  def apply(algorithm: Hmac, requirement: Requirement): com.peknight.jose.jwa.HmacAlgorithm =
    HmacAlgorithm(algorithm, requirement)
end HmacAlgorithm
