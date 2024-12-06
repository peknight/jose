package com.peknight.jose.jwe

import cats.data.NonEmptyList
import cats.effect.Async
import com.peknight.jose.jwx.{JoseConfiguration, JoseHeader}
import com.peknight.error.Error
import fs2.compression.Compression
import scodec.bits.ByteVector

trait JsonWebEncryptionsCompanion:
  def encrypt[F[_]: Async: Compression](primitives: NonEmptyList[EncryptionPrimitive], header: JoseHeader,
                                        plaintext: ByteVector, cekOverride: Option[ByteVector] = None,
                                        ivOverride: Option[ByteVector] = None, aadOverride: Option[ByteVector] = None,
                                        sharedHeader: Option[JoseHeader] = None,
                                        configuration: JoseConfiguration = JoseConfiguration.default)
  : F[Either[Error, JsonWebEncryptions]] =

    ???
end JsonWebEncryptionsCompanion
