package com.peknight.jose.jwa.encryption

import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.functor.*
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.base.Base64UrlNoPad
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.jose.jwk.JsonWebKey
import com.peknight.jose.jwk.JsonWebKey.RSAJsonWebKey
import com.peknight.security.cipher.AES

trait `RSA-OAEP-256Companion` extends RSAESAlgorithmPlatform { self: RSAESAlgorithm =>
  override def isAvailable[F[_] : Sync]: F[Boolean] =
    val modulus = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1Wl" +
      "UzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDpre" +
      "cbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_" +
      "7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBI" +
      "Y2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU" +
      "7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw"
    val exponent = "AQAB"
    val eitherT =
      for
        modulus <- Base64UrlNoPad.fromString(modulus).eLiftET[F]
        exponent <- Base64UrlNoPad.fromString(exponent).eLiftET[F]
        publicKey <- EitherT(RSAJsonWebKey(modulus, exponent).toPublicKey[F]())
        _ <- EitherT(encryptKey[F](publicKey, 16, AES).asError)
      yield
        ()
    eitherT.value.map(_.isRight)
}
