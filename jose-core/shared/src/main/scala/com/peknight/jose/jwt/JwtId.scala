package com.peknight.jose.jwt

import cats.Applicative
import com.peknight.codec.Codec
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.sum.StringType

case class JwtId(value: String)
object JwtId:
  given stringCodecJwtId[F[_]: Applicative]: Codec[F, String, String, JwtId] =
    Codec.map[F, String, String, JwtId](_.value)(JwtId.apply)
  given codecJwtId[F[_]: Applicative, S: StringType]: Codec[F, S, Cursor[S], JwtId] = Codec.codecS[F, S, JwtId]
end JwtId
