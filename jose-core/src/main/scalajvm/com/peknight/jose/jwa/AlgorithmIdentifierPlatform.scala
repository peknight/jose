package com.peknight.jose.jwa

import cats.effect.Sync

trait AlgorithmIdentifierPlatform:
  def isAvailable[F[_]: Sync]: F[Boolean]
end AlgorithmIdentifierPlatform
