package com.peknight.jose.error

trait MissingPublicKey extends JoseError:
  override def lowPriorityMessage: Option[String] = Some("Missing public key")
end MissingPublicKey
object MissingPublicKey extends MissingPublicKey
