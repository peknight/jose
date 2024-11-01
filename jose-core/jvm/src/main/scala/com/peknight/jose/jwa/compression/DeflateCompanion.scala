package com.peknight.jose.jwa.compression

import cats.effect.Sync
import cats.syntax.applicative.*

trait DeflateCompanion:
  def isAvailable[F[_]: Sync]: F[Boolean] = true.pure[F]
end DeflateCompanion
