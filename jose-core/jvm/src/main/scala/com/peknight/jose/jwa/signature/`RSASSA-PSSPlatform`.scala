package com.peknight.jose.jwa.signature

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.typed
import scodec.bits.ByteVector

import java.security.{Key, PrivateKey, PublicKey, SecureRandom, Provider as JProvider}


trait `RSASSA-PSSPlatform` extends RSASSAPlatform { self: `RSASSA-PSS` =>
  def handleSign[F[_] : Sync](key: Key, data: ByteVector, useLegacyName: Boolean = false,
                              random: Option[SecureRandom] = None, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, ByteVector]] =
    typed[PrivateKey](key).map(privateKey => self.signPS[F](privateKey, data, useLegacyName, random, provider).asError)
      .fold(_.asLeft.pure, identity)

  def handleVerify[F[_] : Sync](key: Key, data: ByteVector, signed: ByteVector, useLegacyName: Boolean = false,
                                provider: Option[Provider | JProvider] = None): F[Either[Error, Boolean]] =
    typed[PublicKey](key)
      .map(publicKey => self.publicKeyVerifyPS[F](publicKey, data, signed, useLegacyName, provider).asError)
      .fold(_.asLeft.pure, identity)
}
