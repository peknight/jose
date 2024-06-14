package com.peknight.jose.jwa.ecc

import com.peknight.security.ecc.sec.secp256r1
import com.peknight.security.spec.ECGenParameterSpecName

trait prime256v1 extends Curve:
  def std: ECGenParameterSpecName = secp256r1
  def name: String = "prime256v1"
end prime256v1
object prime256v1 extends prime256v1
