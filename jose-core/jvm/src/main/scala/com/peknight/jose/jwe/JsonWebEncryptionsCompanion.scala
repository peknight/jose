package com.peknight.jose.jwe

import cats.data.NonEmptyList
import cats.effect.Async
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.either.label
import com.peknight.jose.encryptionAlgorithmLabel
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
      encryptionAlgorithm <- elementConsistent(primitives)(_.recipientHeader.flatMap(_.encryptionAlgorithm))
        .label(encryptionAlgorithmLabel)
      encryptionAlgorithm <- encryptionAlgorithm.orElse(commonHeader.encryptionAlgorithm)
        .toRight(OptionEmpty.label(encryptionAlgorithmLabel))
    yield
      ()
    ???
    
  
end JsonWebEncryptionsCompanion
