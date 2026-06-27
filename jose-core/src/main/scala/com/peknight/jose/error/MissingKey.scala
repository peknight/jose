package com.peknight.jose.error

trait MissingKey extends JoseError:
  override protected def lowPriorityMessage: Option[String] = Some("Missing key")
end MissingKey
object MissingKey extends MissingKey
