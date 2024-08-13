package com.peknight.jose.jwa.ecc

import com.peknight.security.ecc.sec.secp256k1
import com.peknight.security.spec.ECGenParameterSpecName

trait `P-256K` extends Curve with `P-256KPlatform`:
  def std: ECGenParameterSpecName = secp256k1
  def name: String = "P-256K"
end `P-256K`
object `P-256K` extends `P-256K`
