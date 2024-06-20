package com.peknight.jose.jwk

import cats.data.NonEmptyList
import com.peknight.codec.base.{Base64, Base64Url}
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwk.JsonWebKey.RSAJsonWebKey
import org.http4s.Uri

import java.math.BigInteger
import java.security.interfaces.{RSAPrivateCrtKey, RSAPrivateKey, RSAPublicKey}

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

end JsonWebKeyPlatform
