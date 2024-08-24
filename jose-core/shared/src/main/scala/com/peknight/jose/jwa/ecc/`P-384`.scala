package com.peknight.jose.jwa.ecc

import com.peknight.security.ecc.sec.secp384r1

trait `P-384` extends Curve with secp384r1:
  def name: String = "P-384"
end `P-384`
object `P-384` extends `P-384`
