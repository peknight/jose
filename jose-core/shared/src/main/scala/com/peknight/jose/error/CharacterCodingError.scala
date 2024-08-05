package com.peknight.jose.error

import java.nio.charset.CharacterCodingException

case class CharacterCodingError(e: CharacterCodingException) extends JsonWebSignatureEncodingError:
  override def lowPriorityMessage: Option[String] =
    Some(s"character coding error${Option(e).flatMap(ee => Option(ee.getMessage)).filterNot(_.isBlank).fold("")(msg => s": $msg")}")
end CharacterCodingError
