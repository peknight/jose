package com.peknight.jose.error

import com.peknight.error.Error

import scala.reflect.ClassTag

trait UnsupportedKey extends JoseError:
  def algorithm: String
  def keyType: Class[?]
  override protected def lowPriorityMessage: Option[String] =
    Some(s"Unsupported key (alg=$algorithm) ${Error.errorClass(keyType)}")
end UnsupportedKey
object UnsupportedKey:
  private case class UnsupportedKey(algorithm: String, keyType: Class[?])
    extends com.peknight.jose.error.UnsupportedKey
  def apply[A](algorithm: String, a: A): com.peknight.jose.error.UnsupportedKey =
    UnsupportedKey(algorithm, a.getClass)
end UnsupportedKey
