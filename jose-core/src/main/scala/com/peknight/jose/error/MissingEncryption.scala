package com.peknight.jose.error

trait MissingEncryption extends JoseError:
  override def lowPriorityMessage: Option[String] = Some("Missing encryption")
end MissingEncryption
object MissingEncryption extends MissingEncryption
