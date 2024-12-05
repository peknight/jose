package com.peknight.jose.error

trait MissingSignature extends JoseError:
  override protected def lowPriorityMessage: Option[String] = Some("Missing signature")
end MissingSignature
object MissingSignature extends MissingSignature
