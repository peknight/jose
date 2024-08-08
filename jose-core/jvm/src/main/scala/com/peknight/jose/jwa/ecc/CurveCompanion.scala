package com.peknight.jose.jwa.ecc

import java.security.spec.EllipticCurve

trait CurveCompanion:
  val curveList: List[Curve & ECParameterSpecCompanion] = List(`P-256`, `P-256K`, `P-384`, `P-521`)
  val curveMap: Map[EllipticCurve, Curve] = curveList.map(curve => (curve.ecParameterSpec.getCurve, curve)).toMap
end CurveCompanion
