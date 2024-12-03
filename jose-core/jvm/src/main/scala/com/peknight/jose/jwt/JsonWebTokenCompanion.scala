package com.peknight.jose.jwt

import cats.Monad
import cats.data.EitherT
import cats.effect.Async
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.Error
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwe.JsonWebEncryption
import com.peknight.jose.jws.JsonWebSignature
import fs2.compression.Compression

trait JsonWebTokenCompanion:
  def parse[F[_]: Async: Compression](jwt: String): F[Either[Error, JsonWebTokenClaims]] =
    Monad[[X] =>> EitherT[F, Error, X]].tailRecM[String, JsonWebTokenClaims](jwt) { jwt =>
      for
        structure <- JsonWebEncryption.parse(jwt).orElse(JsonWebSignature.parse(jwt)).asError.eLiftET[F]
      yield
        ???
    }
    ???
end JsonWebTokenCompanion
