package com.peknight.jose.jwa.signature

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.error.NoSuchCurve
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.typed
import scodec.bits.ByteVector

import java.security.interfaces.{ECKey, ECPrivateKey, ECPublicKey}
import java.security.{Key, PrivateKey, PublicKey, SecureRandom, Provider as JProvider}

trait ECDSAPlatform extends SignaturePlatform { self: ECDSA =>
  def handleSign[F[_] : Sync](key: Key, data: ByteVector, useLegacyName: Boolean = false,
                              random: Option[SecureRandom] = None, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, ByteVector]] =
    typed[PrivateKey](key).map(privateKey => self.signES[F](privateKey, data, random = random, provider = provider))
      .fold(_.asLeft.pure, identity)

  def handleVerify[F[_] : Sync](key: Key, data: ByteVector, signed: ByteVector, useLegacyName: Boolean = false,
                                provider: Option[Provider | JProvider] = None): F[Either[Error, Boolean]] =
    typed[PublicKey](key).map(publicKey => self.publicKeyVerifyES[F](publicKey, data, signed, provider = provider))
      .fold(_.asLeft.pure, identity)

  def validateSigningKey(key: Key): Either[Error, Unit] =
    typed[ECPrivateKey](key).flatMap(validateKey)

  def validateVerificationKey(key: Key): Either[Error, Unit] =
    typed[ECPublicKey](key).flatMap(validateKey)

  def validateKey(key: ECKey): Either[Error, Unit] =
    Curve.curveMap.get(self.curve.ecParameterSpec.getCurve).toRight(NoSuchCurve).as(())

  def isAvailable[F[_]: Sync]: F[Boolean] = self.getSignature[F]().asError.map(_.isRight)
}
