package com.peknight.jose.jwk.ops

import cats.effect.Sync
import cats.syntax.functor.*
import com.peknight.io.ByteArrayInputStream
import com.peknight.security.cert.CertificateFactory
import com.peknight.security.certificate.factory.X509
import com.peknight.security.provider.Provider
import scodec.bits.ByteVector

import java.security.Provider as JProvider
import java.security.cert.X509Certificate

object X509Ops:
  def fromBytes[F[_]: Sync](bytes: ByteVector, provider: Option[Provider | JProvider] = None): F[X509Certificate] =
    CertificateFactory.generateCertificate[F](X509, ByteArrayInputStream(bytes), provider).map(_.asInstanceOf[X509Certificate])
end X509Ops
