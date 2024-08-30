package com.peknight.jose.jwe

import cats.Monad
import cats.data.NonEmptyList
import com.peknight.codec.Decoder.decodeOptionAOU
import com.peknight.codec.Encoder.encodeNonEmptyListA
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.DecodingFailure
import com.peknight.codec.sum.*
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.commons.string.cases.SnakeCase
import com.peknight.commons.string.syntax.cases.to
import com.peknight.jose.jwe.Recipient
import com.peknight.jose.jwe.Recipient.codecRecipient
import com.peknight.jose.jwx.JoseHeader.codecJoseHeader
import com.peknight.jose.jwx.{HeaderEither, JoseHeader}
import io.circe.{Json, JsonObject}

case class JsonWebEncryptions(
                                headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)],
                                sharedHeader: Option[JoseHeader],
                                recipients: NonEmptyList[Recipient],
                                initializationVector: Base64UrlNoPad,
                                ciphertext: Base64UrlNoPad,
                                authenticationTag: Base64UrlNoPad,
                                additionalAuthenticatedData: Option[Base64UrlNoPad]
                              ) extends HeaderEither with JsonWebEncryptionsPlatform:
  def toList: NonEmptyList[JsonWebEncryption] =
    recipients.map(recipient => JsonWebEncryption(headerEither, sharedHeader, recipient.recipientHeader,
      recipient.encryptedKey, initializationVector, ciphertext, authenticationTag, additionalAuthenticatedData
    ))
end JsonWebEncryptions
object JsonWebEncryptions extends JsonWebEncryptionsCompanion:
  private[jwe] val memberNameMap: Map[String, String] = Recipient.memberNameMap ++ Map(
    "headerEither" -> "protected",
    "sharedHeader" -> "unprotected",
    "initializationVector" -> "iv",
    "authenticationTag" -> "tag",
    "additionalAuthenticatedData" -> "aad"
  )

  given codecJsonWebEncryptions[F[_], S](using
    monad: Monad[F],
    objectType: ObjectType[S],
    arrayType: ArrayType[S],
    nullType: NullType[S],
    stringType: StringType[S],
    jsonObjectEncoder: Encoder[F, S, JsonObject],
    jsonObjectDecoder: Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], JsonWebEncryptions] =
    given CodecConfiguration = CodecConfiguration.default
      .withTransformMemberNames(memberName => memberNameMap.getOrElse(memberName, memberName.to(SnakeCase)))
    Codec.derived[F, S, JsonWebEncryptions]

  given jsonCodecJsonWebEncryptions[F[_]: Monad]: Codec[F, Json, Cursor[Json], JsonWebEncryptions] =
    codecJsonWebEncryptions[F, Json]

  given circeCodecJsonWebEncryptions: io.circe.Codec[JsonWebEncryptions] = codec[JsonWebEncryptions]
end JsonWebEncryptions
