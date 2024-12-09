package com.peknight.jose.jwk

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType

case class KeyId(value: String) derives CanEqual
object KeyId:
  given stringCodecKeyId[F[_]: Applicative]: Codec[F, String, String, KeyId] =
    Codec.map[F, String, String, KeyId](_.value)(KeyId.apply)
  given codecKeyId[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], KeyId] = Codec.codecS[F, S, KeyId]
end KeyId
