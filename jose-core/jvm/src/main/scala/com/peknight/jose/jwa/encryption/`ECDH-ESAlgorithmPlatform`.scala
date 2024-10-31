package com.peknight.jose.jwa.encryption

import cats.Foldable
import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.flatMap.*
import cats.syntax.functor.*
import cats.syntax.option.*
import com.peknight.cats.ext.syntax.eitherT.{eLiftET, lLiftET, rLiftET}
import com.peknight.cats.instances.scodec.bits.byteVector.given
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.error.*
import com.peknight.jose.jwa.AlgorithmIdentifier
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwe.ContentEncryptionKeys
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.security.Security
import com.peknight.security.digest.{MessageDigestAlgorithm, `SHA-256`}
import com.peknight.security.ecc.EC
import com.peknight.security.key.agreement.{DiffieHellman, KeyAgreement, XDH}
import com.peknight.security.provider.Provider
import com.peknight.security.spec.SecretKeySpecAlgorithm
import com.peknight.security.syntax.algorithmParameterSpec.generateKeyPair as paramsGenerateKeyPair
import com.peknight.security.syntax.ecParameterSpec.{checkPointOnCurve, generateKeyPair as ecGenerateKeyPair}
import com.peknight.security.syntax.messageDigest.{digestF, getDigestLengthF, updateF}
import com.peknight.validation.std.either.typed
import fs2.Stream
import scodec.bits.ByteVector

import java.security.interfaces.*
import java.security.spec.NamedParameterSpec
import java.security.{Key, KeyPair, PrivateKey, PublicKey, SecureRandom, Provider as JProvider}

trait `ECDH-ESAlgorithmPlatform` { self: `ECDH-ESAlgorithm` =>
  def encryptKey[F[_]: Sync](managementKey: Key,
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
        keyPair <- generateKeyPair[F](managementKey, random, keyPairGeneratorProvider)
        partyVPublicKey <- typed[PublicKey](managementKey).eLiftET
        partyUPrivateKey = keyPair.getPrivate
        keyAgreementAlgorithm = getKeyAgreementAlgorithm(partyUPrivateKey)
        z <- EitherT(keyAgreementAlgorithm.generateSecret[F](partyUPrivateKey, partyVPublicKey,
          provider = keyAgreementProvider).asError)
        derivedKey <- kdf[F](`SHA-256`, z, cekLength, encryptionAlgorithm, agreementPartyUInfo,
          agreementPartyVInfo, messageDigestProvider)
        ephemeralPublicKey <- JsonWebKey.fromPublicKey(keyPair.getPublic).eLiftET
      yield
        ContentEncryptionKeys(derivedKey, ByteVector.empty, Some(ephemeralPublicKey))
    eitherT.value

  def decryptKey[F[_]: Sync](managementKey: Key,
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
        privateKey <- typed[PrivateKey](managementKey).eLiftET
        ephemeralPublicKey <- ephemeralPublicKey match
          case Some(ecPublicKey: ECPublicKey) => checkECKeyForDecrypt(privateKey, ecPublicKey).as(ecPublicKey).eLiftET
          case Some(publicKey) => publicKey.rLiftET
          case _ => MissingPublicKey.lLiftET
        keyAgreementAlgorithm = getKeyAgreementAlgorithm(privateKey)
        z <- EitherT(keyAgreementAlgorithm.generateSecret[F](privateKey, ephemeralPublicKey,
          provider = keyAgreementProvider).asError)
        derivedKey <- kdf[F](`SHA-256`, z, cekLength, encryptionAlgorithm, agreementPartyUInfo,
          agreementPartyVInfo, messageDigestProvider)
      yield
        cekAlgorithm.secretKeySpec(derivedKey).asInstanceOf[Key]
    eitherT.value

  def validateEncryptionKey(managementKey: Key, cekLength: Int): Either[JoseError, Unit] =
    if managementKey.isInstanceOf[ECPublicKey] || managementKey.isInstanceOf[XECPublicKey] then ().asRight
    else UnsupportedKey(managementKey.getAlgorithm, managementKey).asLeft

  def validateDecryptionKey(managementKey: Key, cekLength: Int): Either[JoseError, Unit] =
    if managementKey.isInstanceOf[ECPrivateKey] || managementKey.isInstanceOf[XECPrivateKey] then ().asRight
    else UnsupportedKey(managementKey.getAlgorithm, managementKey).asLeft

  def isAvailable[F[_]: Sync]: F[Boolean] =
    isKeyPairAlgorithmAvailable[F](EC).flatMap {
      case true => Security.getAlgorithms[F](KeyAgreement).map(_.exists(_.equalsIgnoreCase(self.algorithm)))
      case false => false.pure[F]
    }

  private def generateKeyPair[F[_]: Sync](managementKey: Key, random: Option[SecureRandom] = None,
                                          provider: Option[Provider | JProvider] = None): EitherT[F, Error, KeyPair] =
    managementKey match
      case receiverKey: ECPublicKey =>
        generateECKeyPair[F](receiverKey, random, provider)
      case receiverKey: XECPublicKey =>
        generateXECKeyPair[F](receiverKey, random, provider)
      case _ =>
        UnsupportedKey(managementKey.getAlgorithm, managementKey).lLiftET

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

  private def kdf[F[_]: Sync](messageDigestAlgorithm: MessageDigestAlgorithm, sharedSecret: ByteVector, cekLength: Int,
                              algorithm: Option[AlgorithmIdentifier], agreementPartyUInfo: Option[ByteVector],
                              agreementPartyVInfo: Option[ByteVector], provider: Option[Provider | JProvider]
                             ): EitherT[F, Error, ByteVector] =
    for
      otherInfo <- otherInfo(cekLength, algorithm, agreementPartyUInfo, agreementPartyVInfo).eLiftET
      derivedKey <- EitherT(kdf[F](messageDigestAlgorithm, sharedSecret, otherInfo, cekLength, provider).asError)
    yield derivedKey

  private def otherInfo(cekLength: Int, algorithm: Option[AlgorithmIdentifier], agreementPartyUInfo: Option[ByteVector],
                        agreementPartyVInfo: Option[ByteVector]): Either[Error, ByteVector] =
    for
      algorithmId <- algorithm.fold(none[ByteVector].asRight[Error])(
        enc => ByteVector.encodeUtf8(enc.identifier).map(_.some).asError
      )
    yield
      val algorithmIdBytes = prependDataLength(algorithmId)
      val partyUInfoBytes = prependDataLength(agreementPartyUInfo)
      val partyVInfoBytes = prependDataLength(agreementPartyVInfo)
      val keyBitLength = cekLength * 8
      val suppPubInfo = ByteVector.fromInt(keyBitLength)
      val suppPrivInfo = ByteVector.empty
      algorithmIdBytes ++ partyUInfoBytes ++ partyVInfoBytes ++ suppPubInfo ++ suppPrivInfo

  private def prependDataLength(data: Option[ByteVector]): ByteVector =
    data.fold(ByteVector.empty)(data => ByteVector.fromInt(data.length.toInt) ++ data)

  private def kdf[F[_]: Sync](messageDigestAlgorithm: MessageDigestAlgorithm, sharedSecret: ByteVector,
                              otherInfo: ByteVector, keyByteLength: Int, provider: Option[Provider | JProvider])
  : F[ByteVector] =
    for
      messageDigest <- messageDigestAlgorithm.getMessageDigest[F](provider)
      digestLength <- messageDigest.getDigestLengthF[F]
      reps = getReps(keyByteLength * 8, digestLength * 8)
      digests <- Stream.emits(1 to reps).evalMap[F, ByteVector] { i =>
        val counterBytes = ByteVector.fromInt(i)
        for
          _ <- messageDigest.updateF[F](counterBytes)
          _ <- messageDigest.updateF[F](sharedSecret)
          _ <- messageDigest.updateF[F](otherInfo)
          digest <- messageDigest.digestF[F]
        yield
          digest
      }.compile.toList
    yield
      val derivedKeyMaterial = Foldable[List].fold[ByteVector](digests)
      if derivedKeyMaterial.length != keyByteLength then
        derivedKeyMaterial.take(keyByteLength)
      else derivedKeyMaterial

  private def getReps(keyBitLength: Int, digestBitLength: Int): Int =
    val repsD: Double = keyBitLength.toFloat / digestBitLength.toFloat
    Math.ceil(repsD).toInt

  private def checkECKeyForDecrypt(privateKey: PrivateKey, ecPublicKey: ECPublicKey): Either[Error, Unit] =
    for
      ecPrivateKey <- typed[ECPrivateKey](privateKey)
      _ <- checkCurveAllowed(ecPrivateKey)
      _ <- ecPrivateKey.getParams.checkPointOnCurve(ecPublicKey.getW)
    yield
      ()
}
