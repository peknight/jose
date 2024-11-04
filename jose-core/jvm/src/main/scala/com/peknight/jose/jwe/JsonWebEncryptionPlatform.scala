package com.peknight.jose.jwe

import cats.data.EitherT
import cats.effect.Async
import cats.syntax.either.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwa.encryption.KeyDecipherMode
import com.peknight.jose.jwe.JsonWebEncryption.handleDecrypt
import com.peknight.security.provider.Provider
import fs2.compression.Compression
import scodec.bits.ByteVector

import java.security.{Key, SecureRandom, Provider as JProvider}

trait JsonWebEncryptionPlatform { self: JsonWebEncryption =>
  def decrypt[F[_]: Async: Compression](managementKey: Key,
                                        doKeyValidation: Boolean = true,
                                        keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                                        random: Option[SecureRandom] = None,
                                        cipherProvider: Option[Provider | JProvider] = None,
                                        keyAgreementProvider: Option[Provider | JProvider] = None,
                                        keyFactoryProvider: Option[Provider | JProvider] = None,
                                        macProvider: Option[Provider | JProvider] = None,
                                        messageDigestProvider: Option[Provider | JProvider] = None
                                       ): F[Either[Error, ByteVector]] =
    val eitherT =
      for
        encryptedKey <- EitherT(self.encryptedKey.decode[F])
        initializationVector <- EitherT(self.initializationVector.decode[F])
        ciphertext <- EitherT(self.ciphertext.decode[F])
        authenticationTag <- EitherT(self.authenticationTag.decode[F])
        additionalAuthenticatedData <- getAdditionalAuthenticatedData.eLiftET
        header <- self.getUnprotectedHeader.eLiftET
        res <- EitherT(handleDecrypt[F](managementKey, encryptedKey, initializationVector, ciphertext,
          authenticationTag, additionalAuthenticatedData, header, doKeyValidation, keyDecipherModeOverride, random,
          cipherProvider, keyAgreementProvider, keyFactoryProvider, macProvider, messageDigestProvider))
      yield
        res
    eitherT.value

  private def getAdditionalAuthenticatedData: Either[Error, ByteVector] =
    self.additionalAuthenticatedData
      .fold(getProtectedHeader)(_.asRight)
      .flatMap(base => ByteVector.encodeAscii(base.value).asError)
}
