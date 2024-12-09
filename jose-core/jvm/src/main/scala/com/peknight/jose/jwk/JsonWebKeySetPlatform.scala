package com.peknight.jose.jwk

import cats.effect.Sync
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.Error
import cats.syntax.eq.*
import com.peknight.jose.jwa.encryption.{`ECDH-ESAlgorithm`, `ECDH-ESWithAESWrapAlgorithm`, `ECDH-ES`}
import com.peknight.jose.jwe.JsonWebEncryption
import com.peknight.jose.jwk.PublicKeyUseType.Encryption

trait JsonWebKeySetPlatform { self: JsonWebKeySet =>
  def filter[F[_]: Sync](jwe: JsonWebEncryption): F[Either[Error, List[JsonWebKey]]] =
    val eitherT =
      for
        header <- jwe.getMergedHeader.eLiftET[F]
      yield
        self.keys.filter(jwk =>
          header.keyID.fold(true)(keyID => jwk.keyID.contains(keyID)) &&
            header.x509CertificateSHA1Thumbprint.fold(true)(x5t => jwk.x509CertificateSHA1Thumbprint.forall(_ === x5t)) &&
            jwk.publicKeyUse.forall(_ == Encryption) &&
            jwk.keyOperations.forall(_.exists(KeyOperationType.decryptOps.contains)) &&
            header.algorithm
              .filter(alg => alg.isInstanceOf[`ECDH-ESAlgorithm`] || alg.isInstanceOf[`ECDH-ESWithAESWrapAlgorithm`])
              .flatMap(_ => header.ephemeralPublicKey).map(_.keyType)
              .fold(true)(_ == jwk.keyType)
        )
    eitherT.value
}

