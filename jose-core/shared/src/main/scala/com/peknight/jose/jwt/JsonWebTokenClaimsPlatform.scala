package com.peknight.jose.jwt

import cats.syntax.functor.*
import com.peknight.error.Error
import com.peknight.error.option.OptionEmpty
import com.peknight.error.syntax.either.label
import com.peknight.validation.collection.iterableOnce.either.{contains, interact}

trait JsonWebTokenClaimsPlatform { self: JsonWebTokenClaims =>
  def expectedIssuers(expected: String*): Either[Error, Unit] =
    issuer.toRight(OptionEmpty).flatMap(issuer => contains(issuer, expected)).label("issuer").as(())
  def expectedSubjects(expected: String*): Either[Error, Unit] =
    subject.toRight(OptionEmpty).flatMap(subject => contains(subject, expected)).label("subject").as(())
  def acceptableAudiences(acceptable: String*): Either[Error, Unit] =
    audience.toRight(OptionEmpty).flatMap(audience => interact(audience, acceptable)).label("audience").as(())
  def requireExpirationTime: Either[Error, Unit] = expirationTime.toRight(OptionEmpty.label("expirationTime")).as(())
  def requireNotBefore: Either[Error, Unit] = notBefore.toRight(OptionEmpty.label("notBefore")).as(())
  def requireIssuedAt: Either[Error, Unit] = issuedAt.toRight(OptionEmpty.label("issuedAt")).as(())
  def requireJwtID: Either[Error, Unit] = jwtID.toRight(OptionEmpty.label("jwtID")).as(())
}