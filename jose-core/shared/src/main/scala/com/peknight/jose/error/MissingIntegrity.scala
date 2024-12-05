package com.peknight.jose.error

trait MissingIntegrity extends JoseError:
  override protected def lowPriorityMessage: Option[String] = Some("Missing integrity")
end MissingIntegrity
object MissingIntegrity extends MissingIntegrity
