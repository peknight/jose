package com.peknight.jose.error

import com.peknight.error.Error
import com.peknight.jose.jwx.JsonWebStructure

trait InvalidJsonWebToken extends JoseError:
  def jwt: String
  def nested: List[JsonWebStructure]
  override def lowPriorityMessage: Option[String] =
    val nestedMsg = Option(nested).filter(_.nonEmpty).map(_.map(_.compact.fold(_.message, identity)).mkString(","))
      .map(m => s", nested: $m").getOrElse("")
    val causeMsg = cause.map(e => s", caused by: ${e.message}").getOrElse("")
    Some(s"InvalidJsonWebToken $jwt$nestedMsg$causeMsg")
end InvalidJsonWebToken
object InvalidJsonWebToken:
  private case class InvalidJsonWebToken(jwt: String, nested: List[JsonWebStructure], override val cause: Option[Error])
    extends com.peknight.jose.error.InvalidJsonWebToken
  def apply(jwt: String, nested: List[JsonWebStructure] = Nil, cause: Option[Error] = None)
  : com.peknight.jose.error.InvalidJsonWebToken =
    InvalidJsonWebToken(jwt, nested, cause)
end InvalidJsonWebToken
