package com.peknight.jose.jwx

import cats.{Applicative, Show}
import cats.data.Ior
import cats.syntax.either.*
import com.peknight.codec.Codec
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType
import com.peknight.error.Error
import com.peknight.jose.jwx.{bytesDecodeToJson, encodeToBase}

private[jose] trait HeaderIor:
  def headerIor: JoseHeader Ior Base64UrlNoPad

  def header: Option[JoseHeader] = headerIor.left

  def `protected`: Option[Base64UrlNoPad] = headerIor.right

  def getUnprotectedHeader: Either[Error, JoseHeader] = HeaderIor.getUnprotectedHeader(headerIor)

  def getProtectedHeader: Either[Error, Base64UrlNoPad] = HeaderIor.getProtectedHeader(headerIor)

  def unsafeGetProtectedHeader: Base64UrlNoPad = HeaderIor.unsafeGetProtectedHeader(headerIor)
end HeaderIor
private[jose] object HeaderIor:
  def header(headerIor: JoseHeader Ior Base64UrlNoPad): Option[JoseHeader] =
    headerIor match
      case Ior.Left(h) => Some(h)
      case Ior.Both(h, _) => Some(h)
      case _ => None

  def `protected`(headerIor: JoseHeader Ior Base64UrlNoPad): Option[Base64UrlNoPad] =
    headerIor match
      case Ior.Right(p) => Some(p)
      case Ior.Both(_, p) => Some(p)
      case _ => None

  def getUnprotectedHeader(headerIor: JoseHeader Ior Base64UrlNoPad): Either[Error, JoseHeader] =
    headerIor match
      case Ior.Left(h) => Right(h)
      case Ior.Both(h, _) => Right(h)
      case Ior.Right(p) => baseDecodeToJson[JoseHeader](p)

  def getProtectedHeader(headerIor: JoseHeader Ior Base64UrlNoPad): Either[Error, Base64UrlNoPad] =
    headerIor match
      case Ior.Right(p) => Right(p)
      case Ior.Both(_, p) => Right(p)
      case Ior.Left(h) => encodeToBase(h, Base64UrlNoPad)

  private def unsafeGetProtectedHeader(headerIor: JoseHeader Ior Base64UrlNoPad): Base64UrlNoPad =
    getProtectedHeader(headerIor).fold(throw _, identity)

  given codecProtectedHeaderIor[F[_] : Applicative, S: {StringType, Show}]
  : Codec[F, S, Cursor[S], JoseHeader Ior Base64UrlNoPad] =
    Base64UrlNoPad.codecBaseS[F, S].imap(p => Ior.Right(p))(unsafeGetProtectedHeader)
end HeaderIor
