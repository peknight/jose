package com.peknight.jose.jwx

import cats.Applicative
import cats.syntax.applicative.*
import cats.syntax.either.*
import cats.syntax.functor.*
import cats.syntax.option.*
import com.peknight.codec.Decoder
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.DecodingFailure
import io.circe.{Json, JsonObject}

trait ExtendedField:
  def ext: JsonObject
  def decodeExt[F[_], A](using applicative: Applicative[F], decoder: Decoder[F, Cursor[Json], A])
  : F[Either[DecodingFailure, A]] =
      decoder.decodeS(Json.fromJsonObject(ext))
end ExtendedField
