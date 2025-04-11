package com.peknight.jose.jwe

import cats.Monad
import cats.data.Ior
import cats.parse.{Parser, Parser0}
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.*
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.commons.text.cases.SnakeCase
import com.peknight.commons.text.syntax.cases.to
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwx.HeaderIor.given
import com.peknight.jose.jwx.{JoseHeader, JsonWebStructure}
import io.circe.{Json, JsonObject}

case class JsonWebEncryption private[jwe] (
                                            headerIor: JoseHeader Ior Base64UrlNoPad,
                                            sharedHeader: Option[JoseHeader],
                                            recipientHeader: Option[JoseHeader],
                                            encryptedKey: Base64UrlNoPad,
                                            initializationVector: Base64UrlNoPad,
                                            ciphertext: Base64UrlNoPad,
                                            authenticationTag: Base64UrlNoPad,
                                            additionalAuthenticatedData: Option[Base64UrlNoPad]
                                          ) extends JsonWebStructure with Recipient with JsonWebEncryptionPlatform:
  def compact: Either[Error, String] =
    getProtectedHeader.map(h =>
      s"${h.value}.${encryptedKey.value}.${initializationVector.value}.${ciphertext.value}.${authenticationTag.value}"
    )
  def getMergedHeader: Either[Error, JoseHeader] =
    getUnprotectedHeader.map(header => mergedHeader(header, sharedHeader, recipientHeader))
end JsonWebEncryption

object JsonWebEncryption extends JsonWebEncryptionCompanion:
  def apply(header: JoseHeader, sharedHeader: Option[JoseHeader], recipientHeader: Option[JoseHeader],
            encryptedKey: Base64UrlNoPad, initializationVector: Base64UrlNoPad, ciphertext: Base64UrlNoPad,
            authenticationTag: Base64UrlNoPad, additionalAuthenticatedData: Option[Base64UrlNoPad]): JsonWebEncryption =
    JsonWebEncryption(Ior.Left(header), sharedHeader, recipientHeader, encryptedKey, initializationVector, ciphertext,
      authenticationTag, additionalAuthenticatedData)

  def apply(`protected`: Base64UrlNoPad, sharedHeader: Option[JoseHeader], recipientHeader: Option[JoseHeader],
            encryptedKey: Base64UrlNoPad, initializationVector: Base64UrlNoPad, ciphertext: Base64UrlNoPad,
            authenticationTag: Base64UrlNoPad, additionalAuthenticatedData: Option[Base64UrlNoPad]): JsonWebEncryption =
    JsonWebEncryption(Ior.Right(`protected`), sharedHeader, recipientHeader, encryptedKey, initializationVector,
      ciphertext, authenticationTag, additionalAuthenticatedData)

  def apply(header: JoseHeader, `protected`: Base64UrlNoPad, sharedHeader: Option[JoseHeader],
            recipientHeader: Option[JoseHeader], encryptedKey: Base64UrlNoPad, initializationVector: Base64UrlNoPad,
            ciphertext: Base64UrlNoPad, authenticationTag: Base64UrlNoPad,
            additionalAuthenticatedData: Option[Base64UrlNoPad]): JsonWebEncryption =
    JsonWebEncryption(Ior.Both(header, `protected`), sharedHeader, recipientHeader, encryptedKey, initializationVector,
      ciphertext, authenticationTag, additionalAuthenticatedData)

  private val jsonWebEncryptionParser: Parser0[JsonWebEncryption] =
    (Base64UrlNoPad.baseParser ~ (Parser.char('.') *> Base64UrlNoPad.baseParser) ~ (Parser.char('.') *> Base64UrlNoPad.baseParser) ~ (Parser.char('.') *> Base64UrlNoPad.baseParser) ~ (Parser.char('.') *> Base64UrlNoPad.baseParser)).map {
      case ((((p, encryptedKey), initializationVector), ciphertext), authenticationTag) =>
        JsonWebEncryption(p, None, None, encryptedKey, initializationVector, ciphertext, authenticationTag, None)
    }

  def parse(value: String): Either[Error, JsonWebEncryption] = jsonWebEncryptionParser.parseAll(value).asError

  given codecJsonWebEncryption[F[_], S](using
    monad: Monad[F],
    objectType: ObjectType[S],
    nullType: NullType[S],
    arrayType: ArrayType[S],
    booleanType: BooleanType[S],
    numberType: NumberType[S],
    stringType: StringType[S],
    jsonObjectEncoder: Encoder[F, S, JsonObject],
    jsonObjectDecoder: Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], JsonWebEncryption] =
    given CodecConfiguration = CodecConfiguration.default
      .withTransformMemberName(memberName => JsonWebEncryptions.memberNameMap.getOrElse(memberName, memberName.to(SnakeCase)))
    Codec.derived[F, S, JsonWebEncryption]

  given jsonCodecJsonWebEncryption[F[_]: Monad]: Codec[F, Json, Cursor[Json], JsonWebEncryption] =
    codecJsonWebEncryption[F, Json]

  given circeCodecJsonWebEncryption: io.circe.Codec[JsonWebEncryption] = codec[JsonWebEncryption]
end JsonWebEncryption
