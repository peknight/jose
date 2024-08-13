package com.peknight.jose.error

import com.peknight.error.Error

import scala.reflect.ClassTag

trait UncheckedPrivateKey[A] extends UncheckedKey[A]:
  override protected def lowPriorityMessage: Option[String] =
    Some(s"Unchecked private key (alg=$algorithm) ${Error.errorClassTag(using keyType)}")
end UncheckedPrivateKey
object UncheckedPrivateKey:
  private case class UncheckedPrivateKey[A](algorithm: String, keyType: ClassTag[A])
    extends com.peknight.jose.error.UncheckedPrivateKey[A]
  def apply[A](algorithm: String)(using keyType: ClassTag[A]): com.peknight.jose.error.UncheckedPrivateKey[A] =
    UncheckedPrivateKey[A](algorithm, keyType)
end UncheckedPrivateKey
