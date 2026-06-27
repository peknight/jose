package com.peknight.jose.error

trait MissingPrivateKey extends JoseError:
  override def lowPriorityMessage: Option[String] = Some("Missing private key")
end MissingPrivateKey
object MissingPrivateKey extends MissingPrivateKey
