package com.peknight.jose.error

trait UncheckedCharset extends JoseError:
  override protected def lowPriorityMessage: Option[String] = Some("Unchecked charset")
end UncheckedCharset
object UncheckedCharset extends UncheckedCharset
