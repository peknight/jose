package com.peknight.jose.jwa.ecc

import java.security.spec.EllipticCurve

trait CurveCompanion:
  val curveMap: Map[EllipticCurve, Curve] = values.map(curve => (curve.std.ecParameterSpec.getCurve, curve)).toMap
end CurveCompanion
