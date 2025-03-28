package com.peknight.jose.jwa.compression

import cats.effect.Concurrent
import com.peknight.error.Error
import fs2.compression.Compression
import scodec.bits.ByteVector

trait CompressionAlgorithmPlatform:
  def compress[F[_]: {Concurrent, Compression}](data: ByteVector): F[ByteVector]
  def decompress[F[_]: {Concurrent, Compression}](compressedData: ByteVector): F[Either[Error, ByteVector]]
end CompressionAlgorithmPlatform
