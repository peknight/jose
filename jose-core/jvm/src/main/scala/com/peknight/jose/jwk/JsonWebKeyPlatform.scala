package com.peknight.jose.jwk

import cats.data.NonEmptyList
import com.peknight.codec.base.{Base64, Base64Url}
import com.peknight.jose.error.{JsonWebKeyCreationError, NoSuchCurve}
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.ecc.Curve
import com.peknight.jose.jwk.JsonWebKey.{EllipticCurveJsonWebKey, RSAJsonWebKey}
import com.peknight.security.algorithm.Algorithm
import com.peknight.security.key.agreement.{X25519, X448, XDH}
import com.peknight.security.signature.{Ed25519, Ed448, EdDSA}
import org.http4s.Uri
import scodec.bits.ByteVector

import java.math.BigInteger
import java.security.{Key, PrivateKey, PublicKey}
import java.security.interfaces.*
import java.security.spec.EllipticCurve
import javax.crypto.SecretKey

trait JsonWebKeyPlatform:

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
    x509CertificateSHA1Thumbprint: Option[Base64Url] = None,
    x509CertificateSHA256Thumbprint: Option[Base64Url] = None
  ): RSAJsonWebKey =
    def mapCrt(f: RSAPrivateCrtKey => BigInteger): Option[Base64Url] =
      rsaPrivateKey.flatMap {
        case d: RSAPrivateCrtKey => Some(Base64Url.fromBigInt(BigInt(f(d))))
        case _ => None
      }
    RSAJsonWebKey(
      Base64Url.fromBigInt(BigInt(rsaPublicKey.getModulus)),
      Base64Url.fromBigInt(BigInt(rsaPublicKey.getPublicExponent)),
      rsaPrivateKey.map(d => Base64Url.fromBigInt(BigInt(d.getPrivateExponent))),
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
    x509CertificateSHA1Thumbprint: Option[Base64Url] = None,
    x509CertificateSHA256Thumbprint: Option[Base64Url] = None
  ): Either[JsonWebKeyCreationError, EllipticCurveJsonWebKey] =
    val ellipticCurve: EllipticCurve = ecPublicKey.getParams.getCurve
    for
      curve <- Curve.curveMap.get(ellipticCurve).orElse(curve).toRight[JsonWebKeyCreationError](NoSuchCurve)
      fieldSize = ellipticCurve.getField.getFieldSize
      xCoordinate = encodeCoordinate(BigInt(ecPublicKey.getW.getAffineX), fieldSize)
      yCoordinate = encodeCoordinate(BigInt(ecPublicKey.getW.getAffineY), fieldSize)
      eccPrivateKey = ecPrivateKey.map(pk => encodeCoordinate(BigInt(pk.getS), fieldSize))
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

  // def fromOctetKeyPairKey(publicKey: PublicKey, )

  private def encodeCoordinate(coordinate: BigInt, fieldSize: Int): Base64Url =
    val notPadded = toByteVectorUnsigned(coordinate)
    val bytesToOutput = (fieldSize + 7) / 8
    val bytes =
      if notPadded.length >= bytesToOutput then notPadded
      else ByteVector.fill(bytesToOutput - notPadded.length)(0) ++ notPadded
    Base64Url.fromByteVector(bytes)

  private def toByteVectorUnsigned(bigInt: BigInt): ByteVector = {
    val bitLen = ((bigInt.bitLength + 7) >> 3) << 3
    val bigBytes = ByteVector(bigInt.toByteArray)
    if bigInt.bitLength % 8 != 0 && (bigInt.bitLength / 8) + 1 == bitLen / 8 then
      bigBytes
    else
      val src = if bigInt.bitLength % 8 == 0 then bigBytes.tail else bigBytes
      val startDst = bitLen / 8 - src.length
      ByteVector.fill(startDst)(0) ++ src
  }

  private val applicableKeyAlgorithms: Set[Algorithm] = Set(Ed448, Ed25519, EdDSA, X25519, X448, XDH)



end JsonWebKeyPlatform
