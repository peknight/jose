package com.peknight.jose.jwa.compression

import com.peknight.error.Error
import fs2.compression.Compression
import scodec.bits.ByteVector

trait CompressionAlgorithmPlatform:
  def compress[F[_]: Compression](data: ByteVector): F[ByteVector]
  def decompress[F[_]: Compression](compressedData: ByteVector): F[Either[Error, ByteVector]]
end CompressionAlgorithmPlatform
