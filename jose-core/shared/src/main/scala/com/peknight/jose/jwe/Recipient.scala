package com.peknight.jose.jwe

import cats.Monad
import com.peknight.codec.Decoder.decodeOptionAOU
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.codec.circe.iso.codec
import com.peknight.codec.circe.sum.jsonType.given
import com.peknight.codec.configuration.CodecConfiguration
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.{ArrayType, NullType, ObjectType, StringType}
import com.peknight.codec.{Codec, Decoder, Encoder}
import com.peknight.commons.string.cases.SnakeCase
import com.peknight.commons.string.syntax.cases.to
import com.peknight.jose.jwx.JoseHeader
import com.peknight.jose.jwx.JoseHeader.codecJoseHeader
import io.circe.{Json, JsonObject}

case class Recipient(recipientHeader: Option[JoseHeader], encryptedKey: Base64UrlNoPad)
object Recipient:
  private[jwe] val memberNameMap: Map[String, String] = Map("recipientHeader" -> "header")

  given codecRecipient[F[_], S](using
    Monad[F], ObjectType[S], ArrayType[S], NullType[S], StringType[S],
    Encoder[F, S, JsonObject], Decoder[F, Cursor[S], JsonObject]
  ): Codec[F, S, Cursor[S], Recipient] =
    given CodecConfiguration = CodecConfiguration.default
      .withTransformMemberNames(memberName => memberNameMap.getOrElse(memberName, memberName.to(SnakeCase)))
    Codec.derived[F, S, Recipient]

  given jsonCodecRecipient[F[_]: Monad]: Codec[F, Json, Cursor[Json], Recipient] = codecRecipient[F, Json]

  given circeCodecRecipient: io.circe.Codec[Recipient] = codec[Recipient]
end Recipient