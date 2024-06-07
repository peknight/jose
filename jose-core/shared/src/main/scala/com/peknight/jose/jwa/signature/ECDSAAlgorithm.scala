package com.peknight.jose.jwa.signature

import com.peknight.security.digest.SHA
import com.peknight.security.signature.ECDSA
import com.peknight.security.spec.ECGenParameterSpecName

trait ECDSAAlgorithm extends JWSAlgorithm with ECDSA:
  def curveName: ECGenParameterSpecName
  override def algorithm: String = s"ES${digest.bitLength}"
end ECDSAAlgorithm

