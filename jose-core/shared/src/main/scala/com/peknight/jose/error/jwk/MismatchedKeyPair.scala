package com.peknight.jose.error.jwk

import com.peknight.error.std.WrongClassTag

import scala.reflect.ClassTag

trait MismatchedKeyPair[A] extends JsonWebKeyError with WrongClassTag[A]
object MismatchedKeyPair:
  private case class MismatchedKeyPair[A](expectedClassTag: ClassTag[A])
    extends com.peknight.jose.error.jwk.MismatchedKeyPair[A]
  def apply[A](using classTag: ClassTag[A]): com.peknight.jose.error.jwk.MismatchedKeyPair[A] =
    MismatchedKeyPair[A](classTag)
end MismatchedKeyPair
