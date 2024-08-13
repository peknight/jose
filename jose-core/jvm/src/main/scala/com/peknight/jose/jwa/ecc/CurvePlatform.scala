package com.peknight.jose.jwa.ecc

import java.security.spec.ECParameterSpec

trait CurvePlatform:
  def ecParameterSpec: ECParameterSpec
end CurvePlatform
