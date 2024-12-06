package com.peknight.jose.jws

import cats.Id
import cats.effect.Sync
import com.peknight.codec.Encoder
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.jose.jwx.{JoseConfiguration, JoseHeader, JosePrimitive}
import io.circe.Json
import scodec.bits.ByteVector

import java.security.Key

case class SigningPrimitive(header: JoseHeader, key: Option[Key] = None,
                            configuration: JoseConfiguration = JoseConfiguration.default) extends JosePrimitive:
  def signBytes[F[_]: Sync](payload: ByteVector): F[Either[Error, JsonWebSignature]] =
    JsonWebSignature.signBytes[F](header, payload, key, configuration)

  def signString[F[_]: Sync](payload: String): F[Either[Error, JsonWebSignature]] =
    JsonWebSignature.signString[F](header, payload, key, configuration)

  def signJson[F[_], A](payload: A)(using Sync[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebSignature]] =
    JsonWebSignature.signJson[F, A](header, payload, key, configuration)

  def sign[F[_]: Sync](payload: String): F[Either[Error, JsonWebSignature]] =
    JsonWebSignature.sign[F](header, payload, key, configuration)

  private[jws] def handleSignSignature[F[_]: Sync, S <: Signature](payload: String)
                                                                  (f: (Base64UrlNoPad, Base64UrlNoPad) => S)
  : F[Either[Error, S]] =
    JsonWebSignature.handleSignSignatureFunc[F, S](header, payload, key, configuration)(f)
end SigningPrimitive
