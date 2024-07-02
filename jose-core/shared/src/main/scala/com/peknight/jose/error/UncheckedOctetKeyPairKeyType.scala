package com.peknight.jose.error

import com.peknight.error.Error

import scala.reflect.ClassTag

trait UncheckedOctetKeyPairKeyType[K] extends OctetKeyPairJsonWebKeyCreationError:
  def keyType: ClassTag[K]
  override protected def lowPriorityMessage: Option[String] =
    Some(s"Unable to determine OKP subtype from ${Error.errorClassTag(using keyType)}")
end UncheckedOctetKeyPairKeyType
object UncheckedOctetKeyPairKeyType:
  private case class UncheckedOctetKeyPairKeyType[K](keyType: ClassTag[K])
    extends com.peknight.jose.error.UncheckedOctetKeyPairKeyType[K]
  def apply[K](using keyType: ClassTag[K]): com.peknight.jose.error.UncheckedOctetKeyPairKeyType[K] =
    UncheckedOctetKeyPairKeyType[K](keyType)
end UncheckedOctetKeyPairKeyType
