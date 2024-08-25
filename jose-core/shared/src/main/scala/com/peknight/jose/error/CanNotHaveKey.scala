package com.peknight.jose.error

object CanNotHaveKey extends JoseError:
  override def lowPriorityMessage: Option[String] = Some("JWS Plaintext (alg=none) must not use a key")
end CanNotHaveKey
