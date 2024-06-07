package com.peknight.jose.jwa.signature

import com.peknight.security.mac.HmacSHA2

trait HmacSHA2Algorithm extends JWSAlgorithm:
  def mac: HmacSHA2
  def algorithm: String = s"HS${mac.digest.bitLength}"
end HmacSHA2Algorithm
