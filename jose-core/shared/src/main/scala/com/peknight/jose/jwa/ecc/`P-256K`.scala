package com.peknight.jose.jwa.ecc

import com.peknight.security.ecc.sec.secp256k1

trait `P-256K` extends Curve with secp256k1:
  def name: String = "P-256K"
end `P-256K`
object `P-256K` extends `P-256K`
