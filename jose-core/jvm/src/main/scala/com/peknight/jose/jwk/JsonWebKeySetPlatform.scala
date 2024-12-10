package com.peknight.jose.jwk

import cats.data.{EitherT, NonEmptyList}
import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.eq.*
import cats.syntax.traverse.*
import cats.{Applicative, Monad}
import com.peknight.cats.ext.syntax.eitherT.{&&, eLiftET, rLiftET}
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.Error
import com.peknight.error.syntax.either.label
import com.peknight.jose.jwa.encryption.{`ECDH-ESAlgorithm`, `ECDH-ESWithAESWrapAlgorithm`}
import com.peknight.jose.jwe.{DecryptionPrimitive, JsonWebEncryption}
import com.peknight.jose.jwk.JsonWebKey.AsymmetricJsonWebKey
import com.peknight.jose.jwk.PublicKeyUseType.{Encryption, Signature}
import com.peknight.jose.jws.{JsonWebSignature, VerificationPrimitive}
import com.peknight.jose.jwx.{JoseConfiguration, JoseHeader, JosePrimitive, JsonWebStructure}
import com.peknight.security.provider.Provider
import com.peknight.validation.collection.list.either.nonEmpty

import java.security.{Key, Provider as JProvider}

trait JsonWebKeySetPlatform { self: JsonWebKeySet =>
  def handleFilter[F[_]: Sync, Primitive <: JosePrimitive](structure: JsonWebStructure, configuration: JoseConfiguration)
                                                          (filter: (JoseHeader, JsonWebKey) => Boolean)
                                                          (f: (Key, JoseConfiguration) => Primitive)
  : F[Either[Error, NonEmptyList[Primitive]]] =
    val eitherT =
      for
        header <- structure.getMergedHeader.eLiftET[F]
        keys <- Monad[[X] =>> EitherT[F, Error, X]]
          .tailRecM[(List[JsonWebKey], List[JsonWebKey]), List[JsonWebKey]]((self.keys, Nil)) {
            case (Nil, acc) => acc.asRight[(List[JsonWebKey], List[JsonWebKey])].rLiftET[F, Error]
            case (jwk :: tail, acc) =>
              ((header.keyID.fold(true)(keyID => jwk.keyID.contains(keyID)) &&
                header.algorithm.flatMap(_.keyType).fold(true)(_ == jwk.keyType) &&
                filter(header, jwk)).rLiftET[F, Error] &&
                filterX509CertificateSHAThumbprint[F](header.x509CertificateSHA1Thumbprint, configuration)(
                  jwk.getX509CertificateSHA1Thumbprint
                ) &&
                filterX509CertificateSHAThumbprint[F](header.x509CertificateSHA256Thumbprint, configuration)(
                  jwk.getX509CertificateSHA256Thumbprint
                ))
                .map {
                  case true => (tail, jwk :: acc).asLeft[List[JsonWebKey]]
                  case false => (tail, acc).asLeft[List[JsonWebKey]]
                }
          }
        primitives <- keys.traverse[[X] =>> EitherT[F, Error, X], Key] {
          case jwk: AsymmetricJsonWebKey =>
            EitherT(jwk.toPrivateKey[F](configuration.keyFactoryProvider)).map(_.asInstanceOf)
          case jwk => EitherT(jwk.toKey[F](configuration.keyFactoryProvider))
        }.map(_.map(key => f(key, configuration)))
        primitives <- nonEmpty(primitives).label("primitives").eLiftET[F]
      yield
        primitives
    eitherT.value

  private def filterX509CertificateSHAThumbprint[F[_]: Applicative](x509CertificateSHAThumbprint: Option[Base64UrlNoPad],
                                                                    configuration: JoseConfiguration)
                                                                   (getX509CertificateSHAThumbprint: (Option[Provider | JProvider], Option[Provider | JProvider]) => F[Either[Error, Option[Base64UrlNoPad]]])
  : EitherT[F, Error, Boolean] =
    x509CertificateSHAThumbprint.fold(true.rLiftET[F, Error])(x5t =>
      EitherT(getX509CertificateSHAThumbprint(configuration.certificateFactoryProvider,
        configuration.messageDigestProvider))
        .map(_.forall(_ === x5t))
    )

  def filterForVerification[F[_]: Sync](jws: JsonWebSignature, configuration: JoseConfiguration)
  : F[Either[Error, NonEmptyList[VerificationPrimitive]]] =
    jws.getUnprotectedHeader match
      case Left(error) => error.asLeft[NonEmptyList[VerificationPrimitive]].pure[F]
      case Right(header) if header.isNoneAlgorithm =>
        NonEmptyList.one(VerificationPrimitive(None, configuration)).asRight[Error].pure[F]
      case _ => handleFilter(jws, configuration)((header, jwk) =>
        jwk.publicKeyUse.forall(_ == Signature) &&
          jwk.keyOperations.forall(_.exists(KeyOperationType.verifyOps.contains))
      )((key, configuration) => VerificationPrimitive(Some(key), configuration))

  def filterForDecryption[F[_]: Sync](jwe: JsonWebEncryption, configuration: JoseConfiguration)
  : F[Either[Error, NonEmptyList[DecryptionPrimitive]]] =
    handleFilter(jwe, configuration)((header, jwk) =>
      jwk.publicKeyUse.forall(_ == Encryption) &&
        jwk.keyOperations.forall(_.exists(KeyOperationType.decryptOps.contains)) &&
        header.algorithm
          .filter(alg => alg.isInstanceOf[`ECDH-ESAlgorithm`] || alg.isInstanceOf[`ECDH-ESWithAESWrapAlgorithm`])
          .flatMap(_ => header.ephemeralPublicKey).map(_.keyType)
          .fold(true)(_ == jwk.keyType)
    )(DecryptionPrimitive.apply)
}

