package com.peknight.jose.http4s

import org.http4s.MediaType

object MediaRange:
  val `application/jose+json`: MediaType = MediaType.unsafeParse("application/jose+json")
end MediaRange