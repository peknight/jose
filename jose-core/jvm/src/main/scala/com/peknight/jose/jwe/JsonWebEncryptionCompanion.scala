package com.peknight.jose.jwe

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.option.*
import cats.{Applicative, Id}
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.{Base, Base64UrlNoPad}
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.jose.jwa.encryption.KeyManagementAlgorithm
import com.peknight.jose.jwx.JoseHeader
import com.peknight.security.provider.Provider
import com.peknight.validation.std.either.typed
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

trait JsonWebEncryptionCompanion:
  def encrypt[F[_]: Sync](managementKey: Key, header: JoseHeader, cekOverride: Option[ByteVector] = None,
                          random: Option[SecureRandom] = None,
                          cipherProvider: Option[Provider | JProvider] = None,
                          keyAgreementProvider: Option[Provider | JProvider] = None,
                          keyPairGeneratorProvider: Option[Provider | JProvider] = None,
                          macProvider: Option[Provider | JProvider] = None,
                          messageDigestProvider: Option[Provider | JProvider] = None
                         ): F[Either[Error, JsonWebEncryption]] =
    val eitherT =
      for
        algorithm <- header.algorithm.toRight(OptionEmpty.label("alg")).eLiftET[F]
        algorithm <- typed[KeyManagementAlgorithm](algorithm).eLiftET
        encryptionAlgorithm <- header.encryptionAlgorithm.toRight(OptionEmpty.label("enc")).eLiftET
        _ <- algorithm.validateEncryptionKey(managementKey, encryptionAlgorithm.cekByteLength).eLiftET
        agreementPartyUInfo <- decode[F](header.agreementPartyUInfo)
        agreementPartyVInfo <- decode[F](header.agreementPartyVInfo)
        initializationVector <- decode[F](header.initializationVector)
        pbes2SaltInput <- decode[F](header.pbes2SaltInput)
        contentEncryptionKeys <- EitherT(algorithm.encryptKey[F](managementKey, encryptionAlgorithm.cekByteLength,
          encryptionAlgorithm.cekAlgorithm, cekOverride, Some(encryptionAlgorithm), agreementPartyUInfo,
          agreementPartyVInfo, initializationVector, pbes2SaltInput, header.pbes2Count, random, cipherProvider,
          keyAgreementProvider, keyPairGeneratorProvider, macProvider, messageDigestProvider))
      yield ()
    ???

  private def decode[F[_]: Applicative](option: Option[Base]): EitherT[F, Error, Option[ByteVector]] =
    option.map(_.decode[Id]) match
      case Some(Right(bytes)) => bytes.some.asRight.eLiftET[F]
      case Some(Left(error)) => error.asLeft.eLiftET[F]
      case None => none.asRight.eLiftET[F]

  private def update(header: JoseHeader, contentEncryptionKeys: ContentEncryptionKeys): JoseHeader =
    header.copy(
      ephemeralPublicKey = contentEncryptionKeys.ephemeralPublicKey.orElse(header.ephemeralPublicKey),
      initializationVector = contentEncryptionKeys.initializationVector.map(Base64UrlNoPad.fromByteVector)
        .orElse(header.initializationVector),
      authenticationTag = contentEncryptionKeys.authenticationTag.map(Base64UrlNoPad.fromByteVector)
        .orElse(header.authenticationTag),
      pbes2SaltInput = contentEncryptionKeys.pbes2SaltInput.map(Base64UrlNoPad.fromByteVector)
        .orElse(header.pbes2SaltInput),
      pbes2Count = contentEncryptionKeys.pbes2Count.orElse(header.pbes2Count)
    )
end JsonWebEncryptionCompanion
