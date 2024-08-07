package com.peknight.jose.error.jwk

trait NoSuchCurve extends JsonWebKeyError:
  override protected def lowPriorityMessage: Option[String] = Some("No such curve")
end NoSuchCurve
object NoSuchCurve extends NoSuchCurve
