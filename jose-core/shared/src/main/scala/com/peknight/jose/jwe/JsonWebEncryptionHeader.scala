package com.peknight.jose.jwe

import cats.Monad
import cats.data.NonEmptyList
import com.peknight.codec.Decoder.decodeOptionAOU
import com.peknight.codec.base.{Base64, Base64Url}
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.http4s.instances.uri.given
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.commons.string.cases.SnakeCase
import com.peknight.commons.string.syntax.cases.to
import com.peknight.jose.JoseHeader
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.compression.JWECompressionAlgorithm
import com.peknight.jose.jwa.encryption.JWEEncryptionAlgorithm
import com.peknight.jose.jwk.{JsonWebKey, KeyId}
import io.circe.{Json, JsonObject}
import org.http4s.Uri

case class JsonWebEncryptionHeader(
                                    algorithm: Option[JsonWebAlgorithm] = None,
                                    encryptionAlgorithm: Option[JWEEncryptionAlgorithm] = None,
                                    compressionAlgorithm: Option[JWECompressionAlgorithm] = None,
                                    jwkSetURL: Option[Uri] = None,
                                    jwk: Option[JsonWebKey] = None,
                                    keyID: Option[KeyId] = None,
                                    x509URL: Option[Uri] = None,
                                    x509CertificateChain: Option[NonEmptyList[Base64]] = None,
                                    x509CertificateSHA1Thumbprint: Option[Base64Url] = None,
                                    x509CertificateSHA256Thumbprint: Option[Base64Url] = None,
                                    `type`: Option[String] = None,
                                    contentType: Option[String] = None,
                                    critical: Option[List[String]] = None,
                                    ext: Option[JsonObject] = None
                                  ) extends JoseHeader
object JsonWebEncryptionHeader:
  private val memberNameMap: Map[String, String] = com.peknight.jose.memberNameMap ++ Map(
    "encryptionAlgorithm" -> "enc",
    "compressionAlgorithm" -> "zip",
  )
  given codecJsonWebEncryptionHeader[F[_], S](using
    Monad[F], ObjectType[S], ArrayType[S], NullType[S], StringType[S],
    Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], JsonWebEncryptionHeader] =
    given CodecConfiguration = CodecConfiguration.default
      .withTransformMemberNames(memberName => memberNameMap.getOrElse(memberName, memberName.to(SnakeCase)))
      .withExtendedField("ext")
    Codec.derived[F, S, JsonWebEncryptionHeader]

  given jsonCodecJsonWebEncryptionHeader[F[_]: Monad]: Codec[F, Json, Cursor[Json], JsonWebEncryptionHeader] =
    codecJsonWebEncryptionHeader[F, Json]

  given circeCodecJsonWebEncryptionHeader: io.circe.Codec[JsonWebEncryptionHeader] =
    codec[JsonWebEncryptionHeader]
end JsonWebEncryptionHeader
