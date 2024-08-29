package com.peknight.jose.jwa.signature

import cats.syntax.either.*
import cats.syntax.functor.*
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
    (if doKeyValidation then validateKey(key) else ().asRight).as(ByteVector.empty)

  def verify(key: Option[Key], data: ByteVector, signed: ByteVector, doKeyValidation: Boolean = true)
  : Either[Error, Boolean] =
    (if doKeyValidation then validateKey(key) else ().asRight).map(_ => signed.isEmpty)

  def validateKey(key: Option[Key]): Either[JoseError, Unit] =
    key.fold(().asRight)(_ => CanNotHaveKey.asLeft)
end none
