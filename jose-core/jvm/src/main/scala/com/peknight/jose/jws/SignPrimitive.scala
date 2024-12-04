package com.peknight.jose.jws

import cats.Id
import cats.effect.Sync
import com.peknight.codec.Encoder
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.jose.jwx.{JoseContext, JoseHeader}
import io.circe.Json
import scodec.bits.ByteVector

import java.security.Key

case class SignPrimitive(header: JoseHeader, key: Option[Key] = None, context: JoseContext = JoseContext.default):
  def signBytes[F[_]: Sync](payload: ByteVector): F[Either[Error, JsonWebSignature]] =
    JsonWebSignature.signBytes[F](header, payload, key, context)

  def signString[F[_]: Sync](payload: String): F[Either[Error, JsonWebSignature]] =
    JsonWebSignature.signString[F](header, payload, key, context)

  def signJson[F[_], A](payload: A)(using Sync[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebSignature]] =
    JsonWebSignature.signJson[F, A](header, payload, key, context)

  def sign[F[_]: Sync](payload: String): F[Either[Error, JsonWebSignature]] =
    JsonWebSignature.sign[F](header, payload, key, context)

  private[jws] def handleSignSignature[F[_]: Sync, S <: Signature](payload: String)
                                                                  (f: (Base64UrlNoPad, Base64UrlNoPad) => S)
  : F[Either[Error, S]] =
    JsonWebSignature.handleSignSignature[F, S](header, payload, key, context)(f)
end SignPrimitive
