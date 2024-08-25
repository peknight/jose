package com.peknight.jose.jwa.signature

import cats.syntax.either.*
import com.peknight.error.Error
import com.peknight.jose.error.{CanNotHaveKey, JoseError}
import com.peknight.jose.jwx.Requirement
import com.peknight.jose.jwx.Requirement.Optional
import com.peknight.security.error.InvalidSignature
import com.peknight.validation.std.either.isTrue
import scodec.bits.ByteVector

import java.security.Key

object none extends JWSAlgorithm with com.peknight.security.algorithm.NONE:
  val requirement: Requirement = Optional
  override def identifier: String = "none"

  def sign(key: Option[Key], data: ByteVector, doKeyValidation: Boolean = true)
  : Either[JoseError, ByteVector] =
    for
      _ <- if doKeyValidation then validateKey(key) else ().asRight
    yield ByteVector.empty

  def verify(key: Option[Key], data: ByteVector, signed: ByteVector, doKeyValidation: Boolean = true)
  : Either[Error, Unit] =
    for
      _ <- if doKeyValidation then validateKey(key) else ().asRight
      _ <- isTrue(signed.length == 0, InvalidSignature)
    yield ()

  def validateKey(key: Option[Key]): Either[JoseError, Unit] =
    key.fold(().asRight)(_ => CanNotHaveKey.asLeft)
end none
