package com.peknight.jose.jwa.signature

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.applicativeError.*
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.error.NoSuchCurve
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.typed
import scodec.bits.ByteVector

import java.security.{Key, PrivateKey, PublicKey, SecureRandom, Provider as JProvider}

trait `RSASSA-PKCS1-v1_5Platform` extends RSASSAPlatform { self: `RSASSA-PKCS1-v1_5` =>
  def handleSign[F[_] : Sync](key: Key, data: ByteVector, useLegacyName: Boolean = false,
                              random: Option[SecureRandom] = None, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, ByteVector]] =
    typed[PrivateKey](key).map(privateKey => self.sign[F](privateKey, data, random = random, provider = provider)
      .attempt.map(_.asError)).fold(_.asLeft.pure, identity)


  def handleVerify[F[_] : Sync](key: Key, data: ByteVector, signed: ByteVector, useLegacyName: Boolean = false,
                                provider: Option[Provider | JProvider] = None): F[Either[Error, Boolean]] =
    typed[PublicKey](key).map(publicKey => self.publicKeyVerify[F](publicKey, data, signed, provider = provider).attempt
      .map(_.asError)).fold(_.asLeft.pure, identity)
}
