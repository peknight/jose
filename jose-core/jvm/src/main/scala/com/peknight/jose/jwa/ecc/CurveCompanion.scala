package com.peknight.jose.jwa.ecc

import java.security.spec.EllipticCurve

trait CurveCompanion:
  val curveMap: Map[EllipticCurve, Curve] = 
    values.filterNot(_ == prime256v1).map(curve => (curve.ecParameterSpec.getCurve, curve)).toMap
end CurveCompanion
