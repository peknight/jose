package com.peknight.jose.jwa.ecc

import com.peknight.security.ecc.sec.secp256r1

trait `P-256` extends Curve with secp256r1:
  def name: String = "P-256"
end `P-256`
object `P-256` extends `P-256`
