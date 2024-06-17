package com.peknight.jose.jwk

import cats.data.NonEmptyList
import com.peknight.codec.base.{Base64, Base64Url}
import com.peknight.jose.jwa.JsonWebAlgorithm
import org.http4s.Uri

/**
 * https://datatracker.ietf.org/doc/html/rfc7517
 */
trait JsonWebKey:
  def keyType: KeyType
  def publicKeyUse: Option[PublicKeyUseType]
  def keyOperations: Option[Seq[KeyOperationType]]
  def algorithm: Option[JsonWebAlgorithm]
  def keyID: Option[KeyId]
  def x509URL: Option[Uri]
  def x509CertificateChain: Option[NonEmptyList[Base64]]
  def x509CertificateSHA1Thumbprint: Option[Base64Url]
  def x509CertificateSHA256Thumbprint: Option[Base64Url]
end JsonWebKey
object JsonWebKey:
  private[jwk] val memberNameMap: Map[String, String] =
    Map(
      "keyType" -> "kty",
      "publicKeyUse" -> "use",
      "keyOperations" -> "key_ops",
      "algorithm" -> "alg",
      "keyID" -> "kid",
      "x509URL" -> "x5u",
      "x509CertificateChain" -> "x5c",
      "x509CertificateSHA1Thumbprint" -> "x5t",
      "x509CertificateSHA256Thumbprint" -> "x5t#S256",
    )
end JsonWebKey
