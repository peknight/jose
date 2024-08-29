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
  def ext: Option[JsonObject]
  def decodeExt[F[_], A](using applicative: Applicative[F], decoder: Decoder[F, Cursor[Json], A])
  : F[Either[DecodingFailure, Option[A]]] =
    ext.fold(none[A].asRight[DecodingFailure].pure[F])(ext =>
      decoder.decodeS(Json.fromJsonObject(ext)).map(_.map(_.some))
    )
end ExtendedField
