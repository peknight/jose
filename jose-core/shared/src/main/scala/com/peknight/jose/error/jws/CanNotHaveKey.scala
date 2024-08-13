package com.peknight.jose.error.jws

object CanNotHaveKey extends JsonWebSignatureError:
  override def lowPriorityMessage: Option[String] = Some("JWS Plaintext (alg=none) must not use a key")
end CanNotHaveKey
