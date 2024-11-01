package com.peknight.jose.jwa.compression

object Deflate extends JWECompressionAlgorithm with DeflateCompanion:
  def algorithm: String = "DEF"
end Deflate
