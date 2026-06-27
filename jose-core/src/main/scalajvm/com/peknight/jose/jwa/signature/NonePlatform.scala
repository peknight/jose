package com.peknight.jose.jwa.signature

import cats.effect.Sync
import cats.syntax.applicative.*

trait NonePlatform:
  def isAvailable[F[_]: Sync]: F[Boolean] = true.pure[F]
end NonePlatform
