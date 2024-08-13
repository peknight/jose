package com.peknight.jose.error.jws

object InvalidECDSASignatureFormat extends JsonWebSignatureError:
  override protected def lowPriorityMessage: Option[String] = Some("Invalid format of ECDSA signature")
end InvalidECDSASignatureFormat
