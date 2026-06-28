package com.peknight.jose.jwa.signature

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.typed
import scodec.bits.ByteVector

import java.security.interfaces.{EdECPrivateKey, EdECPublicKey}
import java.security.{Key, PrivateKey, PublicKey, SecureRandom, Provider as JProvider}

//noinspection DuplicatedCode
trait EdDSAPlatform extends SignaturePlatform { self: EdDSA =>
  def handleSign[F[_] : Sync](key: Key, data: ByteVector, useLegacyName: Boolean = false,
                              random: Option[SecureRandom] = None, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, ByteVector]] =
    typed[PrivateKey](key).map(privateKey => self.sign[F](privateKey, data, random = random, provider = provider).asError)
      .fold(_.asLeft.pure, identity)

  def handleVerify[F[_] : Sync](key: Key, data: ByteVector, signed: ByteVector, useLegacyName: Boolean = false,
                                provider: Option[Provider | JProvider] = None): F[Either[Error, Boolean]] =
    typed[PublicKey](key).map(publicKey => self.publicKeyVerify[F](publicKey, data, signed, provider = provider).asError)
      .fold(_.asLeft.pure, identity)

  def validateSigningKey(key: Key): Either[Error, Unit] = typed[EdECPrivateKey](key).as(())

  def validateVerificationKey(key: Key): Either[Error, Unit] = typed[EdECPublicKey](key).as(())
  
  def isAvailable[F[_]: Sync]: F[Boolean] = self.getSignature[F]().asError.map(_.isRight)
}
