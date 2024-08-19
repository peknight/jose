package com.peknight.jose.jwa.ecc

import com.peknight.security.ecc.sec.secp384r1
import com.peknight.security.spec.ECGenParameterSpecName

trait `P-384` extends Curve:
  def std: ECGenParameterSpecName = secp384r1
  def name: String = "P-384"
end `P-384`
object `P-384` extends `P-384`
