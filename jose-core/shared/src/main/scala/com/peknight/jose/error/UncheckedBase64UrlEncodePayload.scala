package com.peknight.jose.error

trait UncheckedBase64UrlEncodePayload extends JoseError:
  override protected def lowPriorityMessage: Option[String] = Some("Unchecked b64")
end UncheckedBase64UrlEncodePayload
object UncheckedBase64UrlEncodePayload extends UncheckedBase64UrlEncodePayload
