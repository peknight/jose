package com.peknight.jose.jws.ops

import cats.syntax.either.*
import com.peknight.jose.error.jws.{CanNotHaveKey, JsonWebSignatureError}
import scodec.bits.ByteVector

import java.security.Key

object NoneOps:
  def sign(key: Option[Key], data: ByteVector, doKeyValidation: Boolean = true)
  : Either[JsonWebSignatureError, ByteVector] =
    if doKeyValidation then validateKey(key).map(_ => ByteVector.empty) else ByteVector.empty.asRight

  def verify(key: Option[Key], data: ByteVector, signed: ByteVector, doKeyValidation: Boolean = true)
  : Either[JsonWebSignatureError, Boolean] =
    if doKeyValidation then validateKey(key).map(_ => signed.length == 0) else (signed.length == 0).asRight

  def validateKey(key: Option[Key]): Either[JsonWebSignatureError, Unit] =
    key.fold(().asRight)(_ => CanNotHaveKey.asLeft)
end NoneOps
