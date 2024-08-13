package com.peknight.jose.jwa.signature

import java.security.spec.PSSParameterSpec

trait `RSASSA-PSSAlgorithmPlatform` { self: `RSASSA-PSSAlgorithm` =>
  def toPSSParameterSpec: PSSParameterSpec =
    new PSSParameterSpec(self.digest.algorithm, self.mgf.mgf, self.mgf.toMGFParameterSpec(self.digest),
      self.saltLength, PSSParameterSpec.TRAILER_FIELD_BC)
}
