package com.peknight.jose

import cats.Monad
import cats.data.NonEmptyList
import com.peknight.codec.Decoder.decodeOptionAOU
import com.peknight.codec.base.{Base64NoPad, Base64UrlNoPad}
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.http4s.instances.uri.given
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.commons.string.cases.SnakeCase
import com.peknight.commons.string.syntax.cases.to
import com.peknight.jose.jwa.JsonWebAlgorithm
import com.peknight.jose.jwa.compression.JWECompressionAlgorithm
import com.peknight.jose.jwa.encryption.JWEEncryptionAlgorithm
import com.peknight.jose.jwk.{JsonWebKey, KeyId}
import com.peknight.jose.memberNameMap
import io.circe.{Json, JsonObject}
import org.http4s.Uri

case class JoseHeader(
                       algorithm: Option[JsonWebAlgorithm] = None,
                       encryptionAlgorithm: Option[JWEEncryptionAlgorithm] = None,
                       compressionAlgorithm: Option[JWECompressionAlgorithm] = None,
                       jwkSetURL: Option[Uri] = None,
                       jwk: Option[JsonWebKey] = None,
                       keyID: Option[KeyId] = None,
                       x509URL: Option[Uri] = None,
                       x509CertificateChain: Option[NonEmptyList[Base64NoPad]] = None,
                       x509CertificateSHA1Thumbprint: Option[Base64UrlNoPad] = None,
                       x509CertificateSHA256Thumbprint: Option[Base64UrlNoPad] = None,
                       `type`: Option[String] = None,
                       contentType: Option[String] = None,
                       critical: Option[List[String]] = None,
                       // rfc7797
                       base64UrlEncodePayload: Option[Boolean] = None,
                       ext: Option[JsonObject] = None
                     )
object JoseHeader:
  def jwtHeader(algorithm: JsonWebAlgorithm): JoseHeader = JoseHeader(algorithm = Some(algorithm), `type` = Some(jwtType))
  given codecJoseHeader[F[_], S](using
    Monad[F], ObjectType[S], ArrayType[S], NullType[S], StringType[S],
    Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], JoseHeader] =
    given CodecConfiguration = CodecConfiguration.default
      .withTransformMemberNames(memberName => memberNameMap.getOrElse(memberName, memberName.to(SnakeCase)))
      .withExtendedField("ext")
    Codec.derived[F, S, JoseHeader]

  given jsonCodecJoseHeader[F[_]: Monad]: Codec[F, Json, Cursor[Json], JoseHeader] =
    codecJoseHeader[F, Json]

  given circeCodecJoseHeader: io.circe.Codec[JoseHeader] =
    codec[JoseHeader]
end JoseHeader
