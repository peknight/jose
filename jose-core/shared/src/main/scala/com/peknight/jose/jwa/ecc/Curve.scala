package com.peknight.jose.jwa.ecc

import com.peknight.security.spec.ECGenParameterSpecName

trait Curve:
  def std: ECGenParameterSpecName
  def name: String
end Curve
