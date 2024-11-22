package com.peknight.jose.jws

import cats.Id
import cats.effect.Sync
import cats.syntax.applicative.*
import com.peknight.codec.Encoder
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.provider.Provider
import io.circe.Json
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

case class SignPrimitive(header: JoseHeader, key: Option[Key] = None, doKeyValidation: Boolean = true,
                         useLegacyName: Boolean = false, random: Option[SecureRandom] = None,
                         provider: Option[Provider | JProvider] = None):
  def signJson[F[_], A](payload: A)(using Sync[F], Encoder[Id, Json, A]): F[Either[Error, JsonWebSignature]] =
    JsonWebSignature.signJson[F, A](header, payload, key, doKeyValidation, useLegacyName, random, provider)

  def signBytes[F[_]: Sync](payload: ByteVector): F[Either[Error, JsonWebSignature]] =
    JsonWebSignature.signBytes[F](header, payload, key, doKeyValidation, useLegacyName, random, provider)

  def signUtf8[F[_]: Sync](payload: String): F[Either[Error, JsonWebSignature]] =
    JsonWebSignature.signUtf8[F](header, payload, key, doKeyValidation, useLegacyName, random, provider)

  def sign[F[_]: Sync](payload: String): F[Either[Error, JsonWebSignature]] =
    JsonWebSignature.sign[F](header, payload, key, doKeyValidation, useLegacyName, random, provider)

  private[jws] def handleSignSignature[F[_]: Sync, S <: Signature](payload: String)
                                                                  (f: (Base64UrlNoPad, Base64UrlNoPad) => S)
  : F[Either[Error, S]] =
    JsonWebSignature.handleSignSignature[F, S](header, payload, key, doKeyValidation, useLegacyName, random, provider)(f)

end SignPrimitive
