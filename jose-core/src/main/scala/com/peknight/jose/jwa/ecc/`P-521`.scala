package com.peknight.jose.jwa.ecc

import com.peknight.security.ecc.sec.secp521r1

trait `P-521` extends Curve with secp521r1:
  def name: String = "P-521"
end `P-521`
object `P-521` extends `P-521`
