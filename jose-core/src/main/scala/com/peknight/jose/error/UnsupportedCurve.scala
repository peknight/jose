package com.peknight.jose.error

import com.peknight.jose.jwa.ecc.Curve

trait UnsupportedCurve extends JoseError:
  def curve: Curve
  override protected def lowPriorityMessage: Option[String] = Some(s"Unsupported curve: ${curve.name}")
end UnsupportedCurve
object UnsupportedCurve:
  private case class UnsupportedCurve(curve: Curve) extends com.peknight.jose.error.UnsupportedCurve
  def apply(curve: Curve): com.peknight.jose.error.UnsupportedCurve = UnsupportedCurve(curve)
end UnsupportedCurve
