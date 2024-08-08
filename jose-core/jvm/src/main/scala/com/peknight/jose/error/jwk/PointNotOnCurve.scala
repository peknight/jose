package com.peknight.jose.error.jwk

import java.security.spec.ECParameterSpec

case class PointNotOnCurve(x: BigInt, y: BigInt, ecParameterSpec: ECParameterSpec) extends JsonWebKeyError:
  override def lowPriorityMessage: Option[String] = Some(s"Invalid EC JWK: The 'x' and 'y' public coordinate are not on the curve")
end PointNotOnCurve
