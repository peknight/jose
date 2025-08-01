package com.peknight.jose.jwk

import cats.data.{EitherT, NonEmptyList}
import cats.effect.Sync
import cats.syntax.either.*
import cats.syntax.eq.*
import cats.syntax.traverse.*
import cats.{Applicative, Monad}
import com.peknight.cats.ext.syntax.eitherT.{&&, eLiftET, rLiftET}
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.error.syntax.either.label
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.encryption.{`ECDH-ESAlgorithm`, `ECDH-ESWithAESWrapAlgorithm`}
import com.peknight.jose.jwa.signature.ECDSA
import com.peknight.jose.jwe.{DecryptionPrimitive, JsonWebEncryption}
import com.peknight.jose.jwk.JsonWebKey.{AsymmetricJsonWebKey, EllipticCurveJsonWebKey, OctetKeyPairJsonWebKey}
import com.peknight.jose.jwk.PublicKeyUseType.{Encryption, Signature}
import com.peknight.jose.jws.{JsonWebSignature, VerificationPrimitive}
import com.peknight.jose.jwx.{JoseConfig, JoseHeader, JosePrimitive, JsonWebStructure}
import com.peknight.security.provider.Provider
import com.peknight.security.signature.EdDSA
import com.peknight.validation.collection.list.either.nonEmpty

import java.security.{Key, Provider as JProvider}

trait JsonWebKeySetPlatform { self: JsonWebKeySet =>

  private def handleFilter[F[_]: Sync](structure: JsonWebStructure, config: JoseConfig)
                                      (filter: (JoseHeader, JsonWebKey) => Boolean)
  : F[Either[Error, List[JsonWebKey]]] =
    val eitherT =
      for
        header <- structure.getMergedHeader.eLiftET[F]
        keys <- Monad[[X] =>> EitherT[F, Error, X]]
          .tailRecM[(List[JsonWebKey], List[JsonWebKey]), List[JsonWebKey]]((self.keys, Nil)) {
            case (Nil, acc) => acc.reverse.asRight[(List[JsonWebKey], List[JsonWebKey])].rLiftET[F, Error]
            case (jwk :: tail, acc) =>
              ((header.keyID.fold(true)(keyID => jwk.keyID.contains(keyID)) &&
                header.algorithm.fold(true)(algorithm =>
                  filterByKeyTypes(algorithm, jwk) &&
                    filterByECDSACurve(algorithm, jwk) &&
                    filterByEdDSACurve(algorithm, jwk) &&
                    jwk.algorithm.forall(_ == algorithm)) &&
                header.algorithm
                  .filter(alg => alg.isInstanceOf[`ECDH-ESAlgorithm`] || alg.isInstanceOf[`ECDH-ESWithAESWrapAlgorithm`])
                  .flatMap(_ => header.ephemeralPublicKey).map(_.keyType)
                  .fold(true)(_ == jwk.keyType) &&
                filter(header, jwk)).rLiftET[F, Error] &&
                filterX509CertificateSHAThumbprint[F](header.x509CertificateSHA1Thumbprint, config)(
                  jwk.getX509CertificateSHA1Thumbprint
                ) &&
                filterX509CertificateSHAThumbprint[F](header.x509CertificateSHA256Thumbprint, config)(
                  jwk.getX509CertificateSHA256Thumbprint
                ))
                .map {
                  case true => (tail, jwk :: acc).asLeft[List[JsonWebKey]]
                  case false => (tail, acc).asLeft[List[JsonWebKey]]
                }
          }
      yield
        keys
    eitherT.value

  private def handlePrimitives[F[_]: Sync, Primitive <: JosePrimitive](structure: JsonWebStructure, privateKey: Boolean,
                                                                       config: JoseConfig)
                                                                      (filter: (JoseHeader, JsonWebKey) => Boolean)
                                                                      (f: (Key, JoseConfig) => Primitive)
  : F[Either[Error, NonEmptyList[Primitive]]] =
    val eitherT =
      for
        keys <- EitherT(handleFilter[F](structure, config)(filter))
        primitives <- keys.traverse[[X] =>> EitherT[F, Error, X], Key] {
          case jwk: AsymmetricJsonWebKey =>
            if privateKey then EitherT(jwk.toPrivateKey[F](config.keyFactoryProvider)).map(_.asInstanceOf)
            else EitherT(jwk.toPublicKey[F](config.keyFactoryProvider)).map(_.asInstanceOf)
          case jwk => EitherT(jwk.toKey[F](config.keyFactoryProvider))
        }.map(_.map(key => f(key, config)))
        primitives <- nonEmpty(primitives).label("primitives").eLiftET[F]
      yield
        primitives
    eitherT.value

  private def filterByKeyTypes(algorithm: JsonWebAlgorithm, jwk: JsonWebKey): Boolean =
    algorithm.keyTypes match
      case Nil => true
      case keyTypes => keyTypes.contains(jwk.keyType)

  private def filterByECDSACurve(algorithm: JsonWebAlgorithm, jwk: JsonWebKey): Boolean =
    (algorithm, jwk) match
      case (ecdsa: ECDSA, key: EllipticCurveJsonWebKey) => ecdsa.curve === key.curve
      case _ => true

  private def filterByEdDSACurve(algorithm: JsonWebAlgorithm, jwk: JsonWebKey): Boolean =
    (algorithm, jwk) match
      case (edDSA: EdDSA, key: OctetKeyPairJsonWebKey)  => key.curve.isInstanceOf[EdDSA]
      case _ => true

  private def filterX509CertificateSHAThumbprint[F[_]: Applicative](x509CertificateSHAThumbprint: Option[Base64UrlNoPad],
                                                                    config: JoseConfig)
                                                                   (getX509CertificateSHAThumbprint: (Option[Provider | JProvider], Option[Provider | JProvider]) => F[Either[Error, Option[Base64UrlNoPad]]])
  : EitherT[F, Error, Boolean] =
    x509CertificateSHAThumbprint.fold(true.rLiftET[F, Error])(x5t =>
      EitherT(getX509CertificateSHAThumbprint(config.certificateFactoryProvider,
        config.messageDigestProvider))
        .map(_.forall(_ === x5t))
    )

  private def verificationPredict(header: JoseHeader, jwk: JsonWebKey): Boolean =
    jwk.publicKeyUse.forall(_ == Signature) && jwk.keyOperations.forall(_.exists(KeyOperationType.verifyOps.contains))

  def filterForVerification[F[_]: Sync](jws: JsonWebSignature,
                                        config: JoseConfig = JoseConfig.default)
  : F[Either[Error, List[JsonWebKey]]] =
    VerificationPrimitive.handleFilterForVerification[F](jws, config)(
      handleFilter[F](jws, config)(verificationPredict)
    )

  def verificationPrimitives[F[_]: Sync](jws: JsonWebSignature,
                                         config: JoseConfig = JoseConfig.default)
  : F[Either[Error, NonEmptyList[VerificationPrimitive]]] =
    VerificationPrimitive.handleVerificationPrimitivesF[F](jws, config)(
      handlePrimitives(jws, false, config)(verificationPredict)((key, config) =>
        VerificationPrimitive(Some(key), config)
      )
    )

  private def decryptionPredict(header: JoseHeader, jwk: JsonWebKey): Boolean =
    jwk.publicKeyUse.forall(_ == Encryption) && jwk.keyOperations.forall(_.exists(KeyOperationType.decryptOps.contains))

  def filterForDecryption[F[_]: Sync](jwe: JsonWebEncryption,
                                      config: JoseConfig = JoseConfig.default)
  : F[Either[Error, List[JsonWebKey]]] =
    handleFilter[F](jwe, config)(decryptionPredict)

  def decryptionPrimitives[F[_]: Sync](jwe: JsonWebEncryption,
                                       config: JoseConfig = JoseConfig.default)
  : F[Either[Error, NonEmptyList[DecryptionPrimitive]]] =
    handlePrimitives(jwe, true, config)(decryptionPredict)(DecryptionPrimitive.apply)
}

