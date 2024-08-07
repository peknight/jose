package com.peknight.jose.error.jwk

import com.peknight.error.Error

import scala.reflect.ClassTag

trait UncheckedPublicKey[A] extends UncheckedKey[A]:
  override protected def lowPriorityMessage: Option[String] =
    Some(s"Unchecked public key (alg=$algorithm) ${Error.errorClassTag(using keyType)}")
end UncheckedPublicKey
object UncheckedPublicKey:
  private case class UncheckedPublicKey[A](algorithm: String, keyType: ClassTag[A])
    extends com.peknight.jose.error.jwk.UncheckedPublicKey[A]
  def apply[A](algorithm: String)(using keyType: ClassTag[A]): com.peknight.jose.error.jwk.UncheckedPublicKey[A] =
    UncheckedPublicKey[A](algorithm, keyType)
end UncheckedPublicKey
