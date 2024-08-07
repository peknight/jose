package com.peknight.jose.error.jws

import java.nio.charset.CharacterCodingException

case class CharacterCodingError(e: CharacterCodingException) extends JsonWebSignatureError:
  override def lowPriorityMessage: Option[String] =
    Some(s"character coding error${Option(e).flatMap(ee => Option(ee.getMessage)).filterNot(_.isBlank).fold("")(msg => s": $msg")}")
end CharacterCodingError
