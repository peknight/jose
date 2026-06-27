package com.peknight.jose.jwa.compression

object Deflate extends CompressionAlgorithm with DeflateCompanion:
  def algorithm: String = "DEF"
end Deflate
