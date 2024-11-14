package com.peknight.jose.jwk

import cats.data.NonEmptyList
import cats.syntax.either.*
import cats.syntax.option.*
import com.peknight.codec.base.{Base64, Base64UrlNoPad}
import com.peknight.error.Error
import com.peknight.jose.error.{NoSuchCurve, UnsupportedKey}
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwk.JsonWebKey.*
import com.peknight.security.key.agreement.{X25519, X448, XDH}
import com.peknight.security.signature.{Ed25519, Ed448, EdDSA}
import com.peknight.security.spec.NamedParameterSpecName
import com.peknight.security.syntax.ecKey.{rawPrivateKey, rawXCoordinate, rawYCoordinate}
import com.peknight.security.syntax.edECKey.{getParameterSpecName, rawPrivateKey, rawPublicKey}
import com.peknight.security.syntax.rsaKey.*
import com.peknight.security.syntax.xecKey.{getParameterSpecName, rawPrivateKey, rawPublicKey}
import com.peknight.validation.std.either.typed
import io.circe.JsonObject
import org.http4s.Uri
import scodec.bits.ByteVector

import java.security.interfaces.*
import java.security.spec.EllipticCurve
import java.security.{Key, KeyPair, PrivateKey, PublicKey}
import scala.reflect.ClassTag

trait JsonWebKeyCompanion:

  private val octetKeyPairAlgorithm: Set[NamedParameterSpecName] = Set(Ed448, Ed25519, EdDSA, X25519, X448, XDH)

  def fromKey(
    key: Key,
    otherPrimesInfo: Option[Seq[OtherPrimesInfo]] = None,
    curve: Option[Curve] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
    ext: Option[JsonObject] = None
  ): Either[Error, JsonWebKey] =
    key match
      case publicKey: PublicKey =>
        fromPublicKey(publicKey, None, otherPrimesInfo, curve, publicKeyUse, keyOperations, algorithm, keyID, x509URL,
          x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint, ext)
      case privateKey: PrivateKey => UnsupportedKey(privateKey.getAlgorithm, privateKey).asLeft
      case k =>
        fromOctetSequenceKey(k, publicKeyUse, keyOperations, algorithm, keyID, x509URL, x509CertificateChain,
          x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint, ext
        ).asRight

  def fromKeyPair(
    keyPair: KeyPair,
    otherPrimesInfo: Option[Seq[OtherPrimesInfo]] = None,
    curve: Option[Curve] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
    ext: Option[JsonObject] = None
  ): Either[Error, AsymmetricJsonWebKey] =
    fromPublicKey(keyPair.getPublic, Some(keyPair.getPrivate), otherPrimesInfo, curve, publicKeyUse, keyOperations,
      algorithm, keyID, x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint,
      ext
    )

  def fromPublicKey(
    publicKey: PublicKey,
    privateKey: Option[PrivateKey] = None,
    otherPrimesInfo: Option[Seq[OtherPrimesInfo]] = None,
    curve: Option[Curve] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
    ext: Option[JsonObject] = None
  ): Either[Error, AsymmetricJsonWebKey] =
    publicKey match
      case ecPublicKey: ECPublicKey =>
        for
          ecPrivateKeyOption <- typedPrivateKey[ECPrivateKey](privateKey)
          jwk <- fromEllipticCurveKey(ecPublicKey, ecPrivateKeyOption, curve, publicKeyUse, keyOperations, algorithm,
            keyID, x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint, ext)
        yield
          jwk
      case rsaPublicKey: RSAPublicKey =>
        typedPrivateKey[RSAPrivateKey](privateKey)
          .map(rsaPrivateKeyOption => fromRSAKey(rsaPublicKey, rsaPrivateKeyOption, otherPrimesInfo, publicKeyUse,
            keyOperations, algorithm, keyID, x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint,
            x509CertificateSHA256Thumbprint, ext))
      case pubKey if octetKeyPairAlgorithm.exists(algorithm => algorithm.parameterSpecName == pubKey.getAlgorithm) =>
        fromOctetKeyPairKey(pubKey, privateKey, publicKeyUse, keyOperations, algorithm, keyID, x509URL,
          x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint, ext
        )
      case pubKey => UnsupportedKey(pubKey.getAlgorithm, pubKey).asLeft

  def fromEllipticCurveKey(
    ecPublicKey: ECPublicKey,
    ecPrivateKey: Option[ECPrivateKey] = None,
    curve: Option[Curve] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
    ext: Option[JsonObject] = None
  ): Either[Error, EllipticCurveJsonWebKey] =
    val ellipticCurve: EllipticCurve = ecPublicKey.getParams.getCurve
    for
      curve <- Curve.curveMap.get(ellipticCurve).orElse(curve).toRight(NoSuchCurve)
      xCoordinate = Base64UrlNoPad.fromByteVector(ecPublicKey.rawXCoordinate)
      yCoordinate = Base64UrlNoPad.fromByteVector(ecPublicKey.rawYCoordinate)
      eccPrivateKey = ecPrivateKey.map(pk => Base64UrlNoPad.fromByteVector(pk.rawPrivateKey))
    yield
      EllipticCurveJsonWebKey(
        curve,
        xCoordinate,
        yCoordinate,
        eccPrivateKey,
        publicKeyUse,
        keyOperations,
        algorithm,
        keyID,
        x509URL,
        x509CertificateChain,
        x509CertificateSHA1Thumbprint,
        x509CertificateSHA256Thumbprint,
        ext
      )

  def fromRSAKey(
    rsaPublicKey: RSAPublicKey,
    rsaPrivateKey: Option[RSAPrivateKey] = None,
    otherPrimesInfo: Option[Seq[OtherPrimesInfo]] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
    ext: Option[JsonObject] = None
  ): RSAJsonWebKey =
    RSAJsonWebKey(
      Base64UrlNoPad.fromByteVector(rsaPublicKey.rawModulus),
      Base64UrlNoPad.fromByteVector(rsaPublicKey.rawPublicExponent),
      rsaPrivateKey.map(d => Base64UrlNoPad.fromByteVector(d.rawPrivateExponent)),
      rsaPrivateKey.flatMap(_.rawPrimePOption).map(Base64UrlNoPad.fromByteVector),
      rsaPrivateKey.flatMap(_.rawPrimeQOption).map(Base64UrlNoPad.fromByteVector),
      rsaPrivateKey.flatMap(_.rawPrimeExponentPOption).map(Base64UrlNoPad.fromByteVector),
      rsaPrivateKey.flatMap(_.rawPrimeExponentQOption).map(Base64UrlNoPad.fromByteVector),
      rsaPrivateKey.flatMap(_.rawCrtCoefficientOption).map(Base64UrlNoPad.fromByteVector),
      otherPrimesInfo,
      publicKeyUse,
      keyOperations,
      algorithm,
      keyID,
      x509URL,
      x509CertificateChain,
      x509CertificateSHA1Thumbprint,
      x509CertificateSHA256Thumbprint,
      ext
    )

  def fromOctetSequenceKey(
    key: Key,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
    ext: Option[JsonObject] = None
  ): OctetSequenceJsonWebKey =
    OctetSequenceJsonWebKey(
      Base64UrlNoPad.fromByteVector(ByteVector(key.getEncoded)),
      publicKeyUse,
      keyOperations,
      algorithm,
      keyID,
      x509URL,
      x509CertificateChain,
      x509CertificateSHA1Thumbprint,
      x509CertificateSHA256Thumbprint,
      ext
    )

  def fromOctetKeyPairKey(
    publicKey: PublicKey,
    privateKey: Option[PrivateKey] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
    ext: Option[JsonObject] = None
  ): Either[Error, OctetKeyPairJsonWebKey] =
    val either =
      publicKey match
        case xecPublicKey: XECPublicKey =>
          for
            xecPrivateKeyOption <- typedPrivateKey[XECPrivateKey](privateKey)
            curve <- xecPublicKey.getParameterSpecName
            publicKeyBytes <- xecPublicKey.rawPublicKey
            xCoordinate = Base64UrlNoPad.fromByteVector(publicKeyBytes)
            eccPrivateKey = xecPrivateKeyOption
              .map(xecPrivateKey => Base64UrlNoPad.fromByteVector(xecPrivateKey.rawPrivateKey))
          yield
            (curve, xCoordinate, eccPrivateKey)
        case edECPublicKey: EdECPublicKey =>
          for
            edECPrivateKeyOption <- typedPrivateKey[EdECPrivateKey](privateKey)
            curve <- edECPublicKey.getParameterSpecName
            publicKeyBytes <- edECPublicKey.rawPublicKey
            xCoordinate = Base64UrlNoPad.fromByteVector(publicKeyBytes)
            eccPrivateKey = edECPrivateKeyOption
              .map(edECPrivateKey => Base64UrlNoPad.fromByteVector(edECPrivateKey.rawPrivateKey))
          yield
            (curve, xCoordinate, eccPrivateKey)
        case publicKey => UnsupportedKey(publicKey.getAlgorithm, publicKey).asLeft
    either.map { case (curve, xCoordinate, eccPrivateKey) =>
      OctetKeyPairJsonWebKey(
        curve,
        xCoordinate,
        eccPrivateKey,
        publicKeyUse,
        keyOperations,
        algorithm,
        keyID,
        x509URL,
        x509CertificateChain,
        x509CertificateSHA1Thumbprint,
        x509CertificateSHA256Thumbprint,
        ext
      )
    }

  private def typedPrivateKey[K: ClassTag](privateKeyOption: Option[PrivateKey]): Either[Error, Option[K]] =
    privateKeyOption.fold(none[K].asRight[Error])(privateKey => typed[K](privateKey).map(Some.apply))

end JsonWebKeyCompanion
