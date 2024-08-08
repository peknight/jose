package com.peknight.jose.error.jwk

object MissingPrivateKey extends JsonWebKeyError:
  override def lowPriorityMessage: Option[String] = Some("Missing private key")
end MissingPrivateKey
