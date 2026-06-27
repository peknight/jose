package com.peknight.jose.error

import com.peknight.jose.jwx.JoseHeader

trait MissingVerifyPrimitive extends JoseError:
  def header: JoseHeader
  override protected def lowPriorityMessage: Option[String] = Some(s"Missing verify primitive")
end MissingVerifyPrimitive
object MissingVerifyPrimitive:
  private case class MissingVerifyPrimitive(header: JoseHeader) extends com.peknight.jose.error.MissingVerifyPrimitive
  def apply(header: JoseHeader): com.peknight.jose.error.MissingVerifyPrimitive = MissingVerifyPrimitive(header)
end MissingVerifyPrimitive
