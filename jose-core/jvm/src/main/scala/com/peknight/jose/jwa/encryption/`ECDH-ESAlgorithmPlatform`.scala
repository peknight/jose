package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import com.peknight.cats.ext.monad.transformer.syntax.eitherT.{eLiftET, lLiftET}
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.error.{JoseError, NoSuchCurve, UnsupportedCurve, UnsupportedKey}
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.security.key.agreement.XDH
import com.peknight.security.provider.Provider
import com.peknight.security.syntax.algorithmParameterSpec.generateKeyPair as paramsGenerateKeyPair
import com.peknight.security.syntax.ecParameterSpec.generateKeyPair as ecGenerateKeyPair
import com.peknight.validation.std.either.typed
import scodec.bits.ByteVector

import java.security.interfaces.{ECKey, ECPublicKey, ECPrivateKey, XECPublicKey}
import java.security.spec.NamedParameterSpec
import java.security.{Key, KeyPair, PublicKey, SecureRandom, Provider as JProvider}

trait `ECDH-ESAlgorithmPlatform` { self: `ECDH-ESAlgorithm` =>
  def encryptKey[F[_]: Sync](managementKey: Key, contentEncryptionKeyByteLength: Int,
                             cekOverride: Option[ByteVector] = None,
                             random: Option[SecureRandom] = None,
                             keyPairGeneratorProvider: Option[Provider | JProvider] = None,
                             keyAgreementProvider: Option[Provider | JProvider] = None,
                             messageDigestProvider: Option[Provider | JProvider] = None): F[Either[Error, ByteVector]] =
    val eitherT =
      for
        _ <- canNotHaveKey(cekOverride, self).eLiftET
        keyPair <- generateKeyPair[F](managementKey, random, keyPairGeneratorProvider)
        jwk <- JsonWebKey.fromPublicKey(keyPair.getPublic).eLiftET
        otherPartyPublicKey <- typed[PublicKey](managementKey).eLiftET
        thePartyPrivateKey = keyPair.getPrivate
        keyAgreementAlgorithm = thePartyPrivateKey match
          case _: ECPrivateKey => self
          case _ => XDH
        z <- EitherT(keyAgreementAlgorithm.generateSecret[F](thePartyPrivateKey, otherPartyPublicKey,
          provider = keyAgreementProvider).asError)
      yield ByteVector.empty
    eitherT.value

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

}
