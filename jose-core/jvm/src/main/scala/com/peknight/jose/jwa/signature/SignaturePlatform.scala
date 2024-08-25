package com.peknight.jose.jwa.signature

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import com.peknight.error.Error
import com.peknight.jose.jwa.signature.JWSAlgorithm
import com.peknight.security.provider.Provider
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

trait SignaturePlatform { self: JWSAlgorithm =>
  def signJws[F[_]: Sync](key: Key, data: ByteVector, doKeyValidation: Boolean = true, useLegacyName: Boolean = false,
                          random: Option[SecureRandom] = None, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, ByteVector]] =
    (if doKeyValidation then validateSigningKey(key) else ().asRight).map { _ =>
      handleSign[F](key, data, useLegacyName, random, provider)
    }.fold(_.asLeft.pure, identity)

  def verifyJws[F[_]: Sync](key: Key, data: ByteVector, signed: ByteVector, doKeyValidation: Boolean = true,
                            useLegacyName: Boolean = false, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, Unit]] =
    (if doKeyValidation then validateVerificationKey(key) else ().asRight).map { _ =>
      handleVerify[F](key, data, signed, useLegacyName, provider)
    }.fold(_.asLeft.pure, identity)

  def handleSign[F[_]: Sync](key: Key, data: ByteVector, useLegacyName: Boolean = false,
                             random: Option[SecureRandom] = None, provider: Option[Provider | JProvider] = None)
  : F[Either[Error, ByteVector]]
  def handleVerify[F[_]: Sync](key: Key, data: ByteVector, signed: ByteVector, useLegacyName: Boolean = false,
                               provider: Option[Provider | JProvider] = None): F[Either[Error, Unit]]
  def validateSigningKey(key: Key): Either[Error, Unit]
  def validateVerificationKey(key: Key): Either[Error, Unit]
}
