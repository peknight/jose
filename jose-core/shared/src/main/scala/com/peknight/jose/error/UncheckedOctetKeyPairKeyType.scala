package com.peknight.jose.error

import com.peknight.error.Error

trait UncheckedOctetKeyPairKeyType[K] extends OctetKeyPairJsonWebKeyCreationError:
  def keyType: Class[K]
  override protected def lowPriorityMessage: Option[String] =
    Some(s"Unable to determine OKP subtype from ${Error.errorType(keyType)}")
end UncheckedOctetKeyPairKeyType
object UncheckedOctetKeyPairKeyType:
  private case class UncheckedOctetKeyPairKeyType[K](keyType: Class[K])
    extends com.peknight.jose.error.UncheckedOctetKeyPairKeyType[K]
  def apply[K](keyType: Class[K]): com.peknight.jose.error.UncheckedOctetKeyPairKeyType[K] =
    UncheckedOctetKeyPairKeyType(keyType)
end UncheckedOctetKeyPairKeyType
