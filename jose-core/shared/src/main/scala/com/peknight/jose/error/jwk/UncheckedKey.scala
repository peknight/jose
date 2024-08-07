package com.peknight.jose.error.jwk

import com.peknight.error.Error

import scala.reflect.ClassTag

trait UncheckedKey[A] extends JsonWebKeyError:
  def algorithm: String
  def keyType: ClassTag[A]
  override protected def lowPriorityMessage: Option[String] =
    Some(s"Unchecked key (alg=$algorithm) ${Error.errorClassTag(using keyType)}")
end UncheckedKey
object UncheckedKey:
  private case class UncheckedKey[A](algorithm: String, keyType: ClassTag[A])
    extends com.peknight.jose.error.jwk.UncheckedKey[A]
  def apply[A](algorithm: String)(using keyType: ClassTag[A]): com.peknight.jose.error.jwk.UncheckedKey[A] =
    UncheckedKey[A](algorithm, keyType)
end UncheckedKey
