package com.peknight.jose.key

import cats.effect.Sync
import cats.syntax.functor.*
import com.peknight.io.ByteArrayInputStream
import com.peknight.security.cert.CertificateFactory
import com.peknight.security.cert.syntax.certificateFactory.generateCertificateF
import com.peknight.security.certificate.factory.X509
import scodec.bits.ByteVector

import java.security.cert.{X509Certificate, CertificateFactory as JCertificateFactory}

object X509Ops:

  def certificateFactoryF[F[_]: Sync]: F[JCertificateFactory] = CertificateFactory.getInstance[F](X509)

  def fromBytes[F[_]: Sync](bytes: ByteVector, certFactory: JCertificateFactory): F[X509Certificate] =
    certFactory.generateCertificateF[F](ByteArrayInputStream(bytes)).map(_.asInstanceOf[X509Certificate])
end X509Ops
