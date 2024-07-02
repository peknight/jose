package com.peknight.jose.error

import com.peknight.error.Error

import scala.reflect.ClassTag

trait UnsupportedPublicKey[A] extends UnsupportedKey[A]:
  override protected def lowPriorityMessage: Option[String] =
    Some(s"Unsupported public key (alg=$algorithm) ${Error.errorClassTag(using keyType)}")
end UnsupportedPublicKey
object UnsupportedPublicKey:
  private case class UnsupportedPublicKey[A](algorithm: String, keyType: ClassTag[A])
    extends com.peknight.jose.error.UnsupportedKey[A]
  def apply[A](algorithm: String)(using keyType: ClassTag[A]): com.peknight.jose.error.UnsupportedKey[A] =
    UnsupportedPublicKey[A](algorithm, keyType)
end UnsupportedPublicKey
