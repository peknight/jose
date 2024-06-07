package com.peknight.jose.jwa.signature

import com.peknight.jose.jwa.ecc.Curve
import com.peknight.security.digest.MessageDigestAlgorithm

trait ECDSAAlgorithm extends JWSAlgorithm:
  def curve: Curve
  def digest: MessageDigestAlgorithm
  def algorithm: String = s"ES${digest.bitLength}"
end ECDSAAlgorithm

