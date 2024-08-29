package com.peknight.jose.jwe

import cats.Monad
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.*
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.jose.jwx.{HeaderEither, JoseHeader}
import io.circe.JsonObject

case class JsonWebEncryption private[jwe] (
                                            headerEither: Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)],
                                            sharedHeader: Option[JoseHeader],
                                            recipientHeader: Option[JoseHeader],
                                            encryptedKey: Base64UrlNoPad,
                                            initializationVector: Base64UrlNoPad,
                                            ciphertext: Base64UrlNoPad,
                                            authenticationTag: Base64UrlNoPad,
                                            additionalAuthenticatedData: Option[Base64UrlNoPad]
                                          ) extends Recipient with HeaderEither

object JsonWebEncryption extends JsonWebEncryptionCompanion:
  def apply(header: JoseHeader, sharedHeader: Option[JoseHeader], recipientHeader: Option[JoseHeader],
            encryptedKey: Base64UrlNoPad, initializationVector: Base64UrlNoPad, ciphertext: Base64UrlNoPad,
            authenticationTag: Base64UrlNoPad, additionalAuthenticatedData: Option[Base64UrlNoPad]): JsonWebEncryption =
    JsonWebEncryption(Left(Left(header)), sharedHeader, recipientHeader, encryptedKey, initializationVector, ciphertext,
      authenticationTag, additionalAuthenticatedData)

  def apply(`protected`: Base64UrlNoPad, sharedHeader: Option[JoseHeader], recipientHeader: Option[JoseHeader],
            encryptedKey: Base64UrlNoPad, initializationVector: Base64UrlNoPad, ciphertext: Base64UrlNoPad,
            authenticationTag: Base64UrlNoPad, additionalAuthenticatedData: Option[Base64UrlNoPad]): JsonWebEncryption =
    JsonWebEncryption(Left(Right(`protected`)), sharedHeader, recipientHeader, encryptedKey, initializationVector,
      ciphertext, authenticationTag, additionalAuthenticatedData)

  def apply(header: JoseHeader, `protected`: Base64UrlNoPad, sharedHeader: Option[JoseHeader],
            recipientHeader: Option[JoseHeader], encryptedKey: Base64UrlNoPad, initializationVector: Base64UrlNoPad,
            ciphertext: Base64UrlNoPad, authenticationTag: Base64UrlNoPad,
            additionalAuthenticatedData: Option[Base64UrlNoPad]): JsonWebEncryption =
    JsonWebEncryption(Right((header, `protected`)), sharedHeader, recipientHeader, encryptedKey, initializationVector,
      ciphertext, authenticationTag, additionalAuthenticatedData)

  private val memberNameMap: Map[String, String] = Recipient.memberNameMap ++ Map(
    "headerEither" -> "protected",
    "sharedHeader" -> "unprotected",
    "initializationVector" -> "iv",
    "authenticationTag" -> "tag",
    "additionalAuthenticatedData" -> "aad"
  )

  given codecJsonWebEncryption[F[_], S](using
    monad: Monad[F],
    objectType: ObjectType[S],
    arrayType: ArrayType[S],
    nullType: NullType[S],
    stringType: StringType[S],
    numberType: NumberType[S],
    jsonObjectEncoder: Encoder[F, S, JsonObject],
    jsonObjectDecoder: Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], JsonWebEncryption] =
    given Codec[F, S, Cursor[S], Either[Either[JoseHeader, Base64UrlNoPad], (JoseHeader, Base64UrlNoPad)]] =
      Base64UrlNoPad.codecBaseS[F, S]
      ???
    ???
end JsonWebEncryption
