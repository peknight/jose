package com.peknight.jose.jwa.signature

import cats.effect.Sync
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.label
import com.peknight.security.provider.Provider
import com.peknight.validation.spire.math.interval.either.atOrAbove
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

trait HmacSHAPlatform extends SignaturePlatform { self: HmacSHA =>
  def handleSign[F[_]: Sync](key: Key, data: ByteVector, useLegacyName: Boolean = false,
                              random: Option[SecureRandom] = None, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, ByteVector]] =
    self.mac[F](key, data, provider = provider).asError

  def handleVerify[F[_]: Sync](key: Key, data: ByteVector, signed: ByteVector, useLegacyName: Boolean = false,
                                provider: Option[Provider | JProvider] = None): F[Either[Error, Boolean]] =
    self.verify(key, data, signed, provider = provider).asError

  def validateSigningKey(key: Key): Either[Error, Unit] = validateKey(key)

  def validateVerificationKey(key: Key): Either[Error, Unit] = validateKey(key)

  def validateKey(key: Key): Either[Error, Unit] =
    Option(key.getEncoded)
      .toRight(OptionEmpty.label("keyEncoded"))
      .map(_.length * 8)
      .flatMap(bitLength => atOrAbove(bitLength, self.digest.bitLength).label("keyBitLength"))
      .as(())

  def isAvailable[F[_]: Sync]: F[Boolean] = self.getMAC[F]().asError.map(_.isRight)
}
