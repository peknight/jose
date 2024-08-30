package com.peknight.jose.jwx

import cats.Applicative
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.codec.Codec
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.DecodingFailure
import com.peknight.codec.sum.StringType
import com.peknight.error.Error
import com.peknight.jose.jwx.{fromBase, toBase}

private[jose] trait HeaderEither:
  def headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)]

  def header: Option[JoseHeader] = HeaderEither.header(headerEither)

  def `protected`: Option[Base64UrlNoPad] = HeaderEither.`protected`(headerEither)

  def getUnprotectedHeader: Either[Error, JoseHeader] = HeaderEither.getUnprotectedHeader(headerEither)

  def getProtectedHeader: Either[Error, Base64UrlNoPad] = HeaderEither.getProtectedHeader(headerEither)

  def unsafeGetProtectedHeader: Base64UrlNoPad = HeaderEither.unsafeGetProtectedHeader(headerEither)
end HeaderEither
private[jose] object HeaderEither:
  def header(headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)]): Option[JoseHeader] =
    headerEither match
      case Left(Left(h)) => Some(h)
      case Right((h, _)) => Some(h)
      case _ => None

  def `protected`(headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)])
  : Option[Base64UrlNoPad] =
    headerEither match
      case Left(Right(p)) => Some(p)
      case Right((_, p)) => Some(p)
      case _ => None

  def getUnprotectedHeader(headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)])
  : Either[Error, JoseHeader] =
    headerEither match
      case Left(Left(h)) => Right(h)
      case Right((h, _)) => Right(h)
      case Left(Right(p)) => fromBase[JoseHeader](p)

  def getProtectedHeader(headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)])
  : Either[Error, Base64UrlNoPad] =
    headerEither match
      case Left(Right(p)) => Right(p)
      case Right((_, p)) => Right(p)
      case Left(Left(h)) => toBase(h, Base64UrlNoPad)

  private def unsafeGetProtectedHeader(headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)])
  : Base64UrlNoPad =
    getProtectedHeader(headerEither).fold(throw _, identity)

  given codecProtectedHeaderEither[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)]] with
    def decode(t: Cursor[S])
    : F[Either[DecodingFailure, Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)]]] =
      Base64UrlNoPad.codecBaseS[F, S].decode(t).map(_.map(_.asRight[JoseHeader].asLeft[(JoseHeader, Base64UrlNoPad)]))
    def encode(a: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)]): F[S] =
      Base64UrlNoPad.codecBaseS[F, S].encode(unsafeGetProtectedHeader(a))
  end codecProtectedHeaderEither
end HeaderEither
