package com.peknight.jose.jwk

import scala.collection.immutable.SortedSet

case class JWKSet(keys: SortedSet[JsonWebKey])
