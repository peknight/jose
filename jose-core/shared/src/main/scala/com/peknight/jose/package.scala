package com.peknight

import _root_.cats.Applicative
import _root_.cats.syntax.applicative.*
import _root_.cats.syntax.either.*
import _root_.cats.syntax.functor.*
import _root_.cats.syntax.option.*
import _root_.io.circe.{Json, JsonObject}
import com.peknight.codec.Decoder
import com.peknight.codec.cursor.Cursor
import com.peknight.codec.error.DecodingFailure

package object jose:
  private[jose] val memberNameMap: Map[String, String] =
    Map(
      "algorithm" -> "alg",
      "keyID" -> "kid",
      "x509URL" -> "x5u",
      "x509CertificateChain" -> "x5c",
      "x509CertificateSHA1Thumbprint" -> "x5t",
      "x509CertificateSHA256Thumbprint" -> "x5t#S256",

      // headers
      "jwkSetURL" -> "jku",
      "type" -> "typ",
      "contentType" -> "cty",
      "critical" -> "crit",
      "encryptionAlgorithm" -> "enc",
      "compressionAlgorithm" -> "zip",

      // rfc7797
      "base64UrlEncodePayload" -> "b64",
    )

  private[jose] def decodeExt[F[_], A](ext: Option[JsonObject])
                                      (using applicative: Applicative[F], decoder: Decoder[F, Cursor[Json], A])
  : F[Either[DecodingFailure, Option[A]]] =
    ext.fold(none[A].asRight[DecodingFailure].pure[F])(ext =>
      decoder.decodeS(Json.fromJsonObject(ext)).map(_.map(_.some))
    )
end jose
