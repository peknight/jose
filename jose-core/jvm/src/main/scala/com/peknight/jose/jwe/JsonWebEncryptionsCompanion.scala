package com.peknight.jose.jwe

import cats.data.NonEmptyList
import cats.effect.Async
import com.peknight.error.Error
import com.peknight.error.syntax.either.label
import com.peknight.jose.algorithmLabel
import com.peknight.jose.jwx.{JoseConfiguration, JoseHeader}
import com.peknight.validation.collection.nonEmptyList.either.elementConsistent
import fs2.compression.Compression
import scodec.bits.ByteVector

trait JsonWebEncryptionsCompanion:
  def encrypt[F[_]: Async: Compression](primitives: NonEmptyList[EncryptionPrimitive], header: JoseHeader,
                                        plaintext: ByteVector, cekOverride: Option[ByteVector] = None,
                                        ivOverride: Option[ByteVector] = None, aadOverride: Option[ByteVector] = None,
                                        sharedHeader: Option[JoseHeader] = None,
                                        configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, JsonWebEncryptions]] =
    val commonHeader = sharedHeader.fold(header)(_.deepMerge(header))
    for
      algorithm <- elementConsistent(primitives)(_.recipientHeader.flatMap(_.algorithm)).label(algorithmLabel)

      algorithm <- JsonWebEncryption.checkAlgorithm(algorithm.orElse(commonHeader.algorithm))

    yield
      ()
    ???

end JsonWebEncryptionsCompanion
