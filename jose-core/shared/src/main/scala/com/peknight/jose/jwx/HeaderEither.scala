package com.peknight.jose.jwx

import com.peknight.codec.base.Base64UrlNoPad
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

  def unsafeGetProtectedHeader(headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)])
  : Base64UrlNoPad =
    getProtectedHeader(headerEither).fold(throw _, identity)
end HeaderEither
