package com.peknight.jose.error

import com.peknight.error.std.WrongClassTag

import scala.reflect.ClassTag

trait MismatchedKeyPair[A] extends JsonWebKeyCreationError with WrongClassTag[A]
object MismatchedKeyPair:
  private case class MismatchedKeyPair[A](expectedClassTag: ClassTag[A])
    extends com.peknight.jose.error.MismatchedKeyPair[A]
  def apply[A](using classTag: ClassTag[A]): com.peknight.jose.error.MismatchedKeyPair[A] =
    MismatchedKeyPair[A](classTag)
end MismatchedKeyPair
