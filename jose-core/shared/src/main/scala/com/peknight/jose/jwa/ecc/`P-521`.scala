package com.peknight.jose.jwa.ecc

import com.peknight.security.ecc.sec.secp521r1
import com.peknight.security.spec.ECGenParameterSpecName

trait `P-521` extends Curve:
  def std: ECGenParameterSpecName = secp521r1
  def name: String = "P-521"
end `P-521`
object `P-521` extends `P-521` with `P-521Platform`
