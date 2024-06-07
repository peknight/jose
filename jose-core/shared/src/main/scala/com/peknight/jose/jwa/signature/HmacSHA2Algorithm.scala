package com.peknight.jose.jwa.signature

import com.peknight.jose.jwa.signature.JWSAlgorithm
import com.peknight.security.mac.HmacSHA2

trait HmacSHA2Algorithm extends JWSAlgorithm with HmacSHA2:
  override def algorithm: String = s"HS${digest.bitLength}"
end HmacSHA2Algorithm
