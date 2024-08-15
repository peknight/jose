package com.peknight.jose.jwk

import cats.data.NonEmptyList
import cats.syntax.either.*
import cats.syntax.option.*
import com.peknight.codec.base.{Base64NoPad, Base64UrlNoPad}
import com.peknight.jose.error.jwk.*
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwk.JsonWebKey.*
import com.peknight.jose.jwk.ops.{BigIntOps, OctetKeyPairOps}
import com.peknight.security.algorithm.Algorithm
import com.peknight.security.key.agreement.{X25519, X448, XDH}
import com.peknight.security.signature.{Ed25519, Ed448, EdDSA}
import org.http4s.Uri
import scodec.bits.ByteVector

import java.math.BigInteger
import java.security.interfaces.*
import java.security.spec.EllipticCurve
import java.security.{Key, KeyPair, PrivateKey, PublicKey}
import scala.reflect.ClassTag

trait JsonWebKeyCompanion:

  private val applicableKeyAlgorithms: Set[Algorithm] = Set(Ed448, Ed25519, EdDSA, X25519, X448, XDH)

  def fromKey(
    key: Key,
    otherPrimesInfo: Option[Seq[OtherPrimesInfo]] = None,
    curve: Option[Curve] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64NoPad]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None
  ): Either[JsonWebKeyError, JsonWebKey] =
    key match
      case publicKey: PublicKey =>
        fromPublicKey(publicKey, None, otherPrimesInfo, curve, publicKeyUse, keyOperations, algorithm, keyID, x509URL,
          x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint)
      case privateKey: PrivateKey => UnsupportedKey(privateKey.getAlgorithm)(using ClassTag(privateKey.getClass)).asLeft
      case k =>
        fromOctetSequenceKey(k, publicKeyUse, keyOperations, algorithm, keyID, x509URL, x509CertificateChain,
          x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
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
    x509CertificateChain: Option[NonEmptyList[Base64NoPad]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None
  ): Either[JsonWebKeyError, JsonWebKey] =
    fromPublicKey(keyPair.getPublic, Some(keyPair.getPrivate), otherPrimesInfo, curve, publicKeyUse, keyOperations, algorithm, keyID,
      x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint)

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
    x509CertificateChain: Option[NonEmptyList[Base64NoPad]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None
  ): Either[JsonWebKeyError, JsonWebKey] =
    publicKey match
      case ecPublicKey: ECPublicKey =>
        privateKey match
          case Some(ecPrivateKey: ECPrivateKey) =>
            fromEllipticCurveKey(ecPublicKey, Some(ecPrivateKey), curve, publicKeyUse, keyOperations, algorithm, keyID,
              x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
            )
          case Some(privKey) => MismatchedKeyPair(using ClassTag(privKey.getClass)).asLeft
          case None =>
            fromEllipticCurveKey(ecPublicKey, None, curve, publicKeyUse, keyOperations, algorithm, keyID,
              x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
            )
      case rsaPublicKey: RSAPublicKey =>
        privateKey match
          case Some(rsaPrivateKey: RSAPrivateKey) =>
            fromRSAKey(rsaPublicKey, Some(rsaPrivateKey), otherPrimesInfo, publicKeyUse, keyOperations, algorithm,
              keyID, x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
            ).asRight[JsonWebKeyError]
          case Some(privKey) => MismatchedKeyPair(using ClassTag(privKey.getClass)).asLeft
          case None =>
            fromRSAKey(rsaPublicKey, None, otherPrimesInfo, publicKeyUse, keyOperations, algorithm,
              keyID, x509URL, x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
            ).asRight[JsonWebKeyError]
      case pubKey if applicableKeyAlgorithms.exists(algorithm => algorithm.algorithm == pubKey.getAlgorithm) =>
        fromOctetKeyPairKey(pubKey, privateKey, publicKeyUse, keyOperations, algorithm, keyID, x509URL,
          x509CertificateChain, x509CertificateSHA1Thumbprint, x509CertificateSHA256Thumbprint
        )
      case pubKey => UnsupportedKey(pubKey.getAlgorithm)(using ClassTag(pubKey.getClass)).asLeft

  def fromEllipticCurveKey(
    ecPublicKey: ECPublicKey,
    ecPrivateKey: Option[ECPrivateKey] = None,
    curve: Option[Curve] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64NoPad]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None
  ): Either[JsonWebKeyError, EllipticCurveJsonWebKey] =
    val ellipticCurve: EllipticCurve = ecPublicKey.getParams.getCurve
    for
      curve <- Curve.curveMap.get(ellipticCurve).orElse(curve).toRight[JsonWebKeyError](NoSuchCurve)
      minLength = (ellipticCurve.getField.getFieldSize + 7) / 8
      xCoordinate = BigIntOps.toBase(BigInt(ecPublicKey.getW.getAffineX), minLength, Base64UrlNoPad)
      yCoordinate = BigIntOps.toBase(BigInt(ecPublicKey.getW.getAffineY), minLength, Base64UrlNoPad)
      eccPrivateKey = ecPrivateKey.map(pk => BigIntOps.toBase(BigInt(pk.getS), minLength, Base64UrlNoPad))
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
        x509CertificateSHA256Thumbprint
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
    x509CertificateChain: Option[NonEmptyList[Base64NoPad]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None
  ): RSAJsonWebKey =
    def mapCrt(f: RSAPrivateCrtKey => BigInteger): Option[Base64UrlNoPad] =
      rsaPrivateKey.flatMap {
        case d: RSAPrivateCrtKey => Option(f(d)).map(b => BigIntOps.toBase(BigInt(b), Base64UrlNoPad))
        case _ => None
      }
    RSAJsonWebKey(
      BigIntOps.toBase(BigInt(rsaPublicKey.getModulus), Base64UrlNoPad),
      BigIntOps.toBase(BigInt(rsaPublicKey.getPublicExponent), Base64UrlNoPad),
      rsaPrivateKey.map(d => BigIntOps.toBase(BigInt(d.getPrivateExponent), Base64UrlNoPad)),
      mapCrt(_.getPrimeP),
      mapCrt(_.getPrimeQ),
      mapCrt(_.getPrimeExponentP),
      mapCrt(_.getPrimeExponentQ),
      mapCrt(_.getCrtCoefficient),
      otherPrimesInfo,
      publicKeyUse,
      keyOperations,
      algorithm,
      keyID,
      x509URL,
      x509CertificateChain,
      x509CertificateSHA1Thumbprint,
      x509CertificateSHA256Thumbprint
    )

  def fromOctetSequenceKey(
    key: Key,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64NoPad]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None
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
      x509CertificateSHA256Thumbprint
    )

  def fromOctetKeyPairKey(
    publicKey: PublicKey,
    privateKey: Option[PrivateKey] = None,
    publicKeyUse: Option[PublicKeyUseType] = None,
    keyOperations: Option[Seq[KeyOperationType]] = None,
    algorithm: Option[JsonWebAlgorithm] = None,
    keyID: Option[KeyId] = None,
    x509URL: Option[Uri] = None,
    x509CertificateChain: Option[NonEmptyList[Base64NoPad]] = None,
    x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
    x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None
  ): Either[JsonWebKeyError, OctetKeyPairJsonWebKey] =
    for
      keyPairOps <- OctetKeyPairOps.getKeyPairOps(publicKey)
      curve <- keyPairOps.getAlgorithm(publicKey)
      publicKeyBytes <- keyPairOps.rawPublicKey(publicKey)
      xCoordinate = Base64UrlNoPad.fromByteVector(publicKeyBytes)
      privateKeyBytes <- privateKey.fold(none[ByteVector].asRight[JsonWebKeyError])(
        privateK => keyPairOps.rawPrivateKey(privateK).map(_.some)
      )
      eccPrivateKey = privateKeyBytes.map(Base64UrlNoPad.fromByteVector)
    yield
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
        x509CertificateSHA256Thumbprint
      )
end JsonWebKeyCompanion
