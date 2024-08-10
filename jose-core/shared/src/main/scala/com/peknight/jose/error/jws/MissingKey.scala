package com.peknight.jose.error.jws

object MissingKey extends JsonWebSignatureError:
  override protected def lowPriorityMessage: Option[String] = Some("Missing key")
end MissingKey
