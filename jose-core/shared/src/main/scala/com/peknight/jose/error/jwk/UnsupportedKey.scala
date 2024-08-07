package com.peknight.jose.error.jwk

import com.peknight.error.Error

import scala.reflect.ClassTag

trait UnsupportedKey[A] extends JsonWebKeyError:
  def algorithm: String
  def keyType: ClassTag[A]
  override protected def lowPriorityMessage: Option[String] =
    Some(s"Unsupported key (alg=$algorithm) ${Error.errorClassTag(using keyType)}")
end UnsupportedKey
object UnsupportedKey:
  private case class UnsupportedKey[A](algorithm: String, keyType: ClassTag[A])
    extends com.peknight.jose.error.jwk.UnsupportedKey[A]
  def apply[A](algorithm: String)(using keyType: ClassTag[A]): com.peknight.jose.error.jwk.UnsupportedKey[A] =
    UnsupportedKey[A](algorithm, keyType)
end UnsupportedKey
