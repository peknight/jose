package com.peknight.jose.error

object MissingKey extends JoseError:
  override protected def lowPriorityMessage: Option[String] = Some("Missing key")
end MissingKey
