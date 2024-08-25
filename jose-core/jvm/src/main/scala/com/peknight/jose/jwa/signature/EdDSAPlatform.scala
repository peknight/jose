package com.peknight.jose.jwa.signature

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.applicativeError.*
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.security.error.InvalidSignature
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.{isTrue, typed}
import scodec.bits.ByteVector

import java.security.interfaces.{EdECPrivateKey, EdECPublicKey}
import java.security.{Key, PrivateKey, PublicKey, SecureRandom, Provider as JProvider}

trait EdDSAPlatform extends SignaturePlatform { self: EdDSA =>
  def handleSign[F[_] : Sync](key: Key, data: ByteVector, useLegacyName: Boolean = false,
                              random: Option[SecureRandom] = None, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, ByteVector]] =
    typed[PrivateKey](key).map(privateKey => self.sign[F](privateKey, data, random = random, provider = provider)
      .attempt.map(_.asError)).fold(_.asLeft.pure, identity)

  def handleVerify[F[_] : Sync](key: Key, data: ByteVector, signed: ByteVector, useLegacyName: Boolean = false,
                                provider: Option[Provider | JProvider] = None): F[Either[Error, Unit]] =
    typed[PublicKey](key).map(publicKey => self.publicKeyVerify[F](publicKey, data, signed, provider = provider).attempt
      .map(_.asError.flatMap(isTrue(_, InvalidSignature)))).fold(_.asLeft.pure, identity)

  def validateSigningKey(key: Key): Either[Error, Unit] = typed[EdECPrivateKey](key).as(())

  def validateVerificationKey(key: Key): Either[Error, Unit] = typed[EdECPublicKey](key).as(())
}
