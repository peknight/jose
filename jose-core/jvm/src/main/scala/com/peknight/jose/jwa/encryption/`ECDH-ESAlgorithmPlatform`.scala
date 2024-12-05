package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import com.peknight.cats.ext.syntax.eitherT.{eLiftET, lLiftET, rLiftET}
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.error.*
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwe.ContentEncryptionKeys
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.security.Security
import com.peknight.security.digest.`SHA-256`
import com.peknight.security.ecc.EC
import com.peknight.security.key.agreement.{DiffieHellman, KeyAgreement, XDH}
import com.peknight.security.provider.Provider
import com.peknight.security.spec.SecretKeySpecAlgorithm
import com.peknight.security.syntax.algorithmParameterSpec.generateKeyPair as paramsGenerateKeyPair
import com.peknight.security.syntax.ecParameterSpec.{checkPointOnCurve, generateKeyPair as ecGenerateKeyPair}
import com.peknight.validation.std.either.typed
import scodec.bits.ByteVector

import java.security.interfaces.*
import java.security.spec.NamedParameterSpec
import java.security.{Key, KeyPair, PrivateKey, PublicKey, SecureRandom, Provider as JProvider}

trait `ECDH-ESAlgorithmPlatform` { self: `ECDH-ESAlgorithm` =>
  def encryptKey[F[_]: Sync](key: Key,
                             cekLength: Int,
                             cekAlgorithm: SecretKeySpecAlgorithm,
                             cekOverride: Option[ByteVector] = None,
                             encryptionAlgorithm: Option[EncryptionAlgorithm] = None,
                             agreementPartyUInfo: Option[ByteVector] = None,
                             agreementPartyVInfo: Option[ByteVector] = None,
                             initializationVector: Option[ByteVector] = None,
                             pbes2SaltInput: Option[ByteVector] = None,
                             pbes2Count: Option[Long] = None,
                             random: Option[SecureRandom] = None,
                             cipherProvider: Option[Provider | JProvider] = None,
                             keyAgreementProvider: Option[Provider | JProvider] = None,
                             keyPairGeneratorProvider: Option[Provider | JProvider] = None,
                             macProvider: Option[Provider | JProvider] = None,
                             messageDigestProvider: Option[Provider | JProvider] = None
                            ): F[Either[Error, ContentEncryptionKeys]] =
    val eitherT =
      for
        _ <- canNotHaveKey(cekOverride, self).eLiftET
        keyPair <- generateKeyPair[F](key, random, keyPairGeneratorProvider)
        res <- EitherT(handleEncryptKey[F](key, cekLength, keyPair.getPublic, keyPair.getPrivate,
          encryptionAlgorithm, agreementPartyUInfo, agreementPartyVInfo, keyAgreementProvider, messageDigestProvider))
      yield
        res
    eitherT.value

  def handleEncryptKey[F[_]: Sync](key: Key,
                                   cekLength: Int,
                                   ephemeralPublicKey: PublicKey,
                                   ephemeralPrivateKey: PrivateKey,
                                   encryptionAlgorithm: Option[EncryptionAlgorithm] = None,
                                   agreementPartyUInfo: Option[ByteVector] = None,
                                   agreementPartyVInfo: Option[ByteVector] = None,
                                   keyAgreementProvider: Option[Provider | JProvider] = None,
                                   messageDigestProvider: Option[Provider | JProvider] = None
                                  ): F[Either[Error, ContentEncryptionKeys]] =
    val eitherT =
      for
        partyVPublicKey <- typed[PublicKey](key).eLiftET
        keyAgreementAlgorithm = getKeyAgreementAlgorithm(ephemeralPrivateKey)
        z <- EitherT(keyAgreementAlgorithm.generateSecret[F](ephemeralPrivateKey, partyVPublicKey,
          provider = keyAgreementProvider).asError)
        derivedKey <- EitherT(ConcatKeyDerivationFunction.kdf[F](`SHA-256`, z, cekLength, encryptionAlgorithm,
          agreementPartyUInfo, agreementPartyVInfo, messageDigestProvider))
        ephemeralPublicKey <- JsonWebKey.fromPublicKey(ephemeralPublicKey).eLiftET
      yield
        ContentEncryptionKeys(derivedKey, ByteVector.empty, Some(ephemeralPublicKey))
    eitherT.value

  def decryptKey[F[_]: Sync](key: Key,
                             encryptedKey: ByteVector,
                             cekLength: Int,
                             cekAlgorithm: SecretKeySpecAlgorithm,
                             keyDecipherModeOverride: Option[KeyDecipherMode] = None,
                             encryptionAlgorithm: Option[EncryptionAlgorithm] = None,
                             ephemeralPublicKey: Option[PublicKey] = None,
                             agreementPartyUInfo: Option[ByteVector] = None,
                             agreementPartyVInfo: Option[ByteVector] = None,
                             initializationVector: Option[ByteVector] = None,
                             authenticationTag: Option[ByteVector] = None,
                             pbes2SaltInput: Option[ByteVector] = None,
                             pbes2Count: Option[Long] = None,
                             random: Option[SecureRandom] = None,
                             cipherProvider: Option[Provider | JProvider] = None,
                             keyAgreementProvider: Option[Provider | JProvider] = None,
                             macProvider: Option[Provider | JProvider] = None,
                             messageDigestProvider: Option[Provider | JProvider] = None
                            ): F[Either[Error, Key]] =
    val eitherT =
      for
        privateKey <- typed[PrivateKey](key).eLiftET
        ephemeralPublicKey <- ephemeralPublicKey match
          case Some(ecPublicKey: ECPublicKey) => checkECKeyForDecrypt(privateKey, ecPublicKey).as(ecPublicKey).eLiftET
          case Some(publicKey) => publicKey.rLiftET
          case _ => MissingPublicKey.lLiftET
        keyAgreementAlgorithm = getKeyAgreementAlgorithm(privateKey)
        z <- EitherT(keyAgreementAlgorithm.generateSecret[F](privateKey, ephemeralPublicKey,
          provider = keyAgreementProvider).asError)
        derivedKey <- EitherT(ConcatKeyDerivationFunction.kdf[F](`SHA-256`, z, cekLength, encryptionAlgorithm,
          agreementPartyUInfo, agreementPartyVInfo, messageDigestProvider))
      yield
        cekAlgorithm.secretKeySpec(derivedKey).asInstanceOf[Key]
    eitherT.value

  def validateEncryptionKey(key: Key, cekLength: Int): Either[JoseError, Unit] =
    if key.isInstanceOf[ECPublicKey] || key.isInstanceOf[XECPublicKey] then ().asRight
    else UnsupportedKey(key.getAlgorithm, key).asLeft

  def validateDecryptionKey(key: Key, cekLength: Int): Either[JoseError, Unit] =
    if key.isInstanceOf[ECPrivateKey] || key.isInstanceOf[XECPrivateKey] then ().asRight
    else UnsupportedKey(key.getAlgorithm, key).asLeft

  def isAvailable[F[_]: Sync]: F[Boolean] =
    isKeyPairAlgorithmAvailable[F](EC).flatMap {
      case true => Security.getAlgorithms[F](KeyAgreement).map(_.exists(_.equalsIgnoreCase(self.algorithm)))
      case false => false.pure[F]
    }

  private def generateKeyPair[F[_]: Sync](key: Key, random: Option[SecureRandom] = None,
                                          provider: Option[Provider | JProvider] = None): EitherT[F, Error, KeyPair] =
    key match
      case receiverKey: ECPublicKey =>
        generateECKeyPair[F](receiverKey, random, provider)
      case receiverKey: XECPublicKey =>
        generateXECKeyPair[F](receiverKey, random, provider)
      case _ =>
        UnsupportedKey(key.getAlgorithm, key).lLiftET

  private def generateECKeyPair[F[_]: Sync](receiverKey: ECPublicKey, random: Option[SecureRandom] = None,
                                            provider: Option[Provider | JProvider] = None): EitherT[F, Error, KeyPair] =
    for
      _ <- checkCurveAllowed(receiverKey).eLiftET
      keyPair <- EitherT(receiverKey.getParams.ecGenerateKeyPair[F](random, provider).asError)
    yield keyPair

  private def generateXECKeyPair[F[_]: Sync](receiverKey: XECPublicKey, random: Option[SecureRandom] = None,
                                             provider: Option[Provider | JProvider] = None): EitherT[F, Error, KeyPair] =
    for
      params <- typed[NamedParameterSpec](receiverKey.getParams).eLiftET
      keyPair <- EitherT(params.paramsGenerateKeyPair[F](XDH, random, provider).asError)
    yield keyPair

  private def checkCurveAllowed(receiverKey: ECKey): Either[JoseError, Curve] =
    Curve.curveMap.get(receiverKey.getParams.getCurve) match
      case Some(curve) if self.supportedCurves.contains(curve) => curve.asRight
      case Some(curve) => UnsupportedCurve(curve).asLeft
      case None => NoSuchCurve.asLeft

  private def getKeyAgreementAlgorithm(privateKey: PrivateKey): DiffieHellman =
    if privateKey.isInstanceOf[ECPrivateKey] then self else XDH

  private def checkECKeyForDecrypt(privateKey: PrivateKey, ecPublicKey: ECPublicKey): Either[Error, Unit] =
    for
      ecPrivateKey <- typed[ECPrivateKey](privateKey)
      _ <- checkCurveAllowed(ecPrivateKey)
      _ <- ecPrivateKey.getParams.checkPointOnCurve(ecPublicKey.getW)
    yield
      ()
}
