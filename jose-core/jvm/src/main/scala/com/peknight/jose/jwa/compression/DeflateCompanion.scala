package com.peknight.jose.jwa.compression

import cats.effect.{Concurrent, Sync}
import cats.syntax.applicative.*
import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.syntax.applicativeError.asError
import fs2.compression.{Compression, DeflateParams, InflateParams, ZLibParams}
import fs2.{Chunk, Stream}
import scodec.bits.ByteVector

trait DeflateCompanion extends CompressionAlgorithmPlatform:

  def compress[F[_]: {Concurrent, Compression}](data: ByteVector): F[ByteVector] =
    Stream.chunk(Chunk.byteVector(data))
      .through(Compression[F].deflate(DeflateParams(level = DeflateParams.Level.EIGHT, header = ZLibParams.Header.GZIP)))
      .compile
      .toVector
      .map(ByteVector.apply)

  def decompress[F[_]: {Concurrent, Compression}](compressedData: ByteVector): F[Either[Error, ByteVector]] =
    Stream.chunk(Chunk.byteVector(compressedData))
      .through(Compression[F].inflate(InflateParams(header = ZLibParams.Header.GZIP)))
      .compile
      .toVector
      .map(ByteVector.apply)
      .asError

  def isAvailable[F[_]: Sync]: F[Boolean] = true.pure[F]
end DeflateCompanion
