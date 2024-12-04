package com.peknight.jose.jws

import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.error.syntax.applicativeError.asError
import com.peknight.error.syntax.either.asError
import com.peknight.jose.jwk.{e, n}
import com.peknight.security.cipher.RSA
import org.scalatest.flatspec.AsyncFlatSpec

class MaintainEncodedPayloadAndHeaderFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "MaintainEncodedPayloadAndHeader" should "succeed with odd encoded paylaod" in {
    // There's an extra 'X' at the end of the encoded payload but it still decodes to the same value as when the 'X'
    // isn't there; but the signature is over the X and we want to check what was signed rather than what we think
    // should be signed by re-encoding the payload
    val funkyToken = "eyJhbGciOiJSUzI1NiJ9.IVRoaXMgaXMgbm8gbG9uZ2VyIGEgdmFjYXRpb24uX.f6qDgGZ8tCVZ_DhlFwWAZvV-Vv5yQOF" +
      "SAXVv98vOpgkI6YQd6hjCWaeyaWbMWhV__uiWiEY0SutaQw1y71bXvRPfy12YKpyIlRwvos9L5myA--GGc6o88hDjxxc2PLhhhNazR1aSVXIb" +
      "6wF4PJENb10XDMIuMj9wtzDVnLajS5O3Ptygwx39bRa9XoXrAxbSyEBJSV9nVCQS-wPRaEudDcLRQhKVhMHYJ-3UZn0VVpCz_8KWvw4JOB9jW" +
      "ntS85CPF4RcUaepQJ2pz-8gfCrv2qKHKU36FbmqOwKoQZL1dLXH1wp33k7ESt5zivLVPli3tPDVfBa5BmWAMO1mydqGgw"
    val run =
      for
        publicKey <- EitherT(RSA.publicKey[IO](n, e).asError)
        jws <- JsonWebSignature.parse(funkyToken).eLiftET[IO]
        _ <- EitherT(jws.check[IO](Some(publicKey)))
        // payload <- jws.decodePayloadString().eLiftET[IO]
      yield
        // payload == "!This is no longer a vacation."
        true
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end MaintainEncodedPayloadAndHeaderFlatSpec
