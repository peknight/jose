package com.peknight.jose.error

import com.peknight.error.Error

import scala.reflect.ClassTag

trait UnsupportedKey[A] extends JsonWebKeyCreationError:
  def algorithm: String
  def keyType: ClassTag[A]
  override protected def lowPriorityMessage: Option[String] =
    Some(s"Unsupported key (alg=$algorithm) ${Error.errorClassTag(using keyType)}")
end UnsupportedKey
object UnsupportedKey:
  private case class UnsupportedKey[A](algorithm: String, keyType: ClassTag[A])
    extends com.peknight.jose.error.UnsupportedKey[A]
  def apply[A](algorithm: String)(using keyType: ClassTag[A]): com.peknight.jose.error.UnsupportedKey[A] =
    UnsupportedKey[A](algorithm, keyType)
end UnsupportedKey
