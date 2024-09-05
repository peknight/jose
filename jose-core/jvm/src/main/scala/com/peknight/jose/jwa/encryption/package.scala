package com.peknight.jose.jwa

import cats.effect.Sync
import cats.syntax.applicative.*
import cats.syntax.flatMap.*
import com.peknight.security.random.SecureRandom
import com.peknight.security.syntax.secureRandom.nextBytesF
import scodec.bits.ByteVector

import java.security.SecureRandom as JSecureRandom

package object encryption:
  private[encryption] def getBytesOrRandom[F[_]: Sync](byteLength: Int, bytesOverride: Option[ByteVector] = None,
                                                       random: Option[JSecureRandom] = None): F[ByteVector] =
    bytesOverride.fold(random.fold(SecureRandom[F])(_.pure[F]).flatMap(_.nextBytesF[F](byteLength)))(_.pure[F])
end encryption
