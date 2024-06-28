package com.peknight.jose.jwa.ecc

import java.security.spec.EllipticCurve

trait CurvePlatform:
  val curveMap: Map[EllipticCurve, Curve] =
    List(`P-256`, `P-256K`, `P-384`, `P-521`).map(curve => (curve.ecParameterSpec.getCurve, curve)).toMap
end CurvePlatform
