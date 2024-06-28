package com.peknight.jose.jwa.ecc

import java.security.spec.ECParameterSpec

trait ECParameterSpecPlatform:
  def ecParameterSpec: ECParameterSpec
end ECParameterSpecPlatform
