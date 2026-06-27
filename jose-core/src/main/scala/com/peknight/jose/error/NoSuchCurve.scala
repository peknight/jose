package com.peknight.jose.error

trait NoSuchCurve extends JoseError:
  override protected def lowPriorityMessage: Option[String] = Some("No such curve")
end NoSuchCurve
object NoSuchCurve extends NoSuchCurve
