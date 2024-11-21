package com.peknight.jose.jwk

import cats.Id
import cats.data.EitherT
import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.peknight.cats.ext.syntax.eitherT.eLiftET
import com.peknight.codec.circe.parser.decode
import com.peknight.error.option.OptionEmpty
import com.peknight.security.digest.`SHA-1`
import org.scalatest.flatspec.AsyncFlatSpec

class JsonWebKeyThumbprintFlatSpec extends AsyncFlatSpec with AsyncIOSpec:
  "JsonWebKeyThumbprint" should "succeed with RSA from RFC7638 example 3.1" in {
    // http://tools.ietf.org/html/rfc7638#section-3.1
    val n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCi" +
      "FV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0" +
      "zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFC" +
      "ur-kEgU8awapJzKnqDKgw"
    val json =
      s"""
         |{
         |  "kty": "RSA",
         |  "n": "$n",
         |  "e": "AQAB",
         |  "alg": "RS256",
         |  "kid": "2011-04-29"
         |}
      """.stripMargin
    val actual = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    val run =
      for
        jsonWebKey <- decode[Id, JsonWebKey](json).eLiftET[IO]
        thumbprint <- EitherT(jsonWebKey.calculateBase64UrlEncodedThumbprint[IO]())
      yield
        thumbprint.value == actual
    run.value.asserting(value => assert(value.getOrElse(false)))
  }

  "JsonWebKeyThumbprint" should "succeed with kid derivation using jwk thumb compare" in {
    // kid values from an external source that were derived using 7638 JWK thumbprint
    // this test is just to confirm that we get the same value when calculating the 7638 JWK thumbprint
    // (they seem to have also confused the x5t stuff but that's superfluous to this check)

    val jwksJson = "{\"keys\": [{\"e\": \"AQAB\", \"kid\": \"xl16BDxw57JN-3PtvrmyA-zWTgM\", \"kty\": \"RSA\", \"n\":" +
      " \"wNxCV2ShU99ncUqZZyT1gScdjk8Mk6nKX0ejemmueHHyVmPsGQs4B11ARL2bGi_jJabbByDfa6qyl8i-eUAbGuwf6N1uNeBnvAIKdTIQKF" +
      "lwfk6ev3-KXbwpSY53y7XQQx_Fismu1IkMWfhhJ-H-57j9vTlvbF4Ld3xAUAmKr5Zn0wMAG04tS7MySruptK5aoP-fsHVAUKuSbplDzXe3dTQ" +
      "0aue5yLpv1ZQc_tqOEQDpCcL4EROivBUpMvPpXupGzaAxL-N6EKPR2mGIwQatx3wW_ft8QPw4O151g5jGSiEJJ_rJ9VCIRcPEpuQFYVcKEu5u" +
      "9-2O433HKY_ITu46iQ\", \"x5t\": \"xl16BDxw57JN-3PtvrmyA-zWTgM\", \"x5t#256\": \"e9IVUvH7-e1JuynqE7Za0J-dFveSII" +
      "oIUrJEkeAWqUk\", \"x5u\": \"https://keystore.mit.openbanking.qa/VCLDvrRWGoRwROsuCG/xl16BDxw57JN-3PtvrmyA-zWTg" +
      "M.pem\", \"x5c\": [\"MIIFljCCBH6gAwIBAgIEWWwG0jANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJHQjEdMBsGA1UEChMUT3BlbiBC" +
      "YW5raW5nIExpbWl0ZWQxETAPBgNVBAsTCFRlc3QgUEtJMSUwIwYDVQQDExxPcGVuIEJhbmtpbmcgVGVzdCBJc3N1aW5nIENBMB4XDTE3MTIyM" +
      "jEwMTMxNVoXDTE5MDEyMjEwNDMxNVowYDELMAkGA1UEBhMCR0IxHTAbBgNVBAoTFE9wZW4gQmFua2luZyBMaW1pdGVkMREwDwYDVQQLEwhUZX" +
      "N0IFBLSTEfMB0GA1UEAxMWNmRpMkRlODhzOEQyelZYZ3l4bTBiMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMDcQldkoVPfZ3F" +
      "KmWck9YEnHY5PDJOpyl9Ho3pprnhx8lZj7BkLOAddQES9mxov4yWm2wcg32uqspfIvnlAGxrsH+jdbjXgZ7wCCnUyEChZcH5Onr9/il28KUmO" +
      "d8u10EMfxYrJrtSJDFn4YSfh/ue4/b05b2xeC3d8QFAJiq+WZ9MDABtOLUuzMkq7qbSuWqD/n7B1QFCrkm6ZQ813t3U0NGrnuci6b9WUHP7aj" +
      "hEA6QnC+BETorwVKTLz6V7qRs2gMS/jehCj0dphiMEGrcd8Fv37fED8ODtedYOYxkohCSf6yfVQiEXDxKbkBWFXChLubvftjuN9xymPyE7uOo" +
      "kCAwEAAaOCAlAwggJMMA4GA1UdDwEB/wQEAwIGwDAVBgNVHSUEDjAMBgorBgEEAYI3CgMMMIHgBgNVHSAEgdgwgdUwgdIGCysGAQQBqHWBBgF" +
      "kMIHCMCoGCCsGAQUFBwIBFh5odHRwOi8vb2IudHJ1c3Rpcy5jb20vcG9saWNpZXMwgZMGCCsGAQUFBwICMIGGDIGDVXNlIG9mIHRoaXMgQ2Vy" +
      "dGlmaWNhdGUgY29uc3RpdHV0ZXMgYWNjZXB0YW5jZSBvZiB0aGUgT3BlbkJhbmtpbmcgUm9vdCBDQSBDZXJ0aWZpY2F0aW9uIFBvbGljaWVzI" +
      "GFuZCBDZXJ0aWZpY2F0ZSBQcmFjdGljZSBTdGF0ZW1lbnQwOgYIKwYBBQUHAQEELjAsMCoGCCsGAQUFBzABhh5odHRwOi8vb2J0ZXN0LnRydX" +
      "N0aXMuY29tL29jc3AwgcMGA1UdHwSBuzCBuDA3oDWgM4YxaHR0cDovL29idGVzdC50cnVzdGlzLmNvbS9wa2kvb2J0ZXN0aXNzdWluZ2NhLmN" +
      "ybDB9oHugeaR3MHUxCzAJBgNVBAYTAkdCMR0wGwYDVQQKExRPcGVuIEJhbmtpbmcgTGltaXRlZDERMA8GA1UECxMIVGVzdCBQS0kxJTAjBgNV" +
      "BAMTHE9wZW4gQmFua2luZyBUZXN0IElzc3VpbmcgQ0ExDTALBgNVBAMTBENSTDgwHwYDVR0jBBgwFoAUDwHAL+hobPcjv45lbokNxqaFd7cwH" +
      "QYDVR0OBBYEFNczbyn1OqOJZ1kAJRrwLmomI9JVMA0GCSqGSIb3DQEBCwUAA4IBAQBBhSq283S2SfvnjeWpp3nkOEP4SLORINjyUuWjt/ivHS" +
      "nHBJVlVCKyB05BQyyImNUXFtvQD0Hn2k+OTPmPprtPbWVMUaIrTa2aGmCbNLhp5ukPc1GCzSSzR4lpmNOHbL0wxV0uG4Kb+qrSQZlfwx8Kmeo" +
      "gYeaZVOTE6rfzydnNkUi7CJ7AWeOl/aUyIN0w9PDxGAWfa+YS0efx7UwXrv3pitEGo/zP/4Tygsd2lgvlJ/xml2nyVM4oCv5WTyZTMxeC/zqc" +
      "UTouvogJcIqyKcZHSlKaKNQgNaT1Ury9mPGXPi7MraTBB1hFY4g4JDQ5c6YRISoA8pOXyFLIG4zxIrqu\"], \"use\": \"sig\"}, {\"e" +
      "\": \"AQAB\", \"kid\": \"2bag3Pig0ajRgDs8HLF0qNsIoy0\", \"kty\": \"RSA\", \"n\": \"t-nDTUa8Ay22jFSVn3dG3Fzcmb" +
      "jv4tcMovNooIgB3SeMAfpHhjKWj7yFVhyGUbQrmEqFoZB8AR0fEfU_cplx22SyhSMbwAlMsud7eXFpaf9hp28u-O9tNortyuGD81cIMA1t2d8" +
      "UOOW3hyjfFBpPgIlm7LmXco95iLum4auJwVwYQu0xE2Xz7xbRyle39XhHWOIvA39re3Cj7_VCvk1fyshYDrWFVnlMSOJATqqNXwoxsY9K6IfA" +
      "chj1EJU8N0CNLhu1BpyjHM7qrrDP-mEE6FLAWEpe6rzupRcpIWLkRoUol17jVULNHfp5NPgiTxBPsEZybIjnnxI-E2Og4VXJjw\", \"x5t\"" +
      ": \"2bag3Pig0ajRgDs8HLF0qNsIoy0\", \"x5t#256\": \"IXbL0R9gp9qpbLYMc_wnQTtC61pVLkQaxMry7jbLE58\", \"x5u\": \"h" +
      "ttps://keystore.mit.openbanking.qa/VCLDvrRWGoRwROsuCG/2bag3Pig0ajRgDs8HLF0qNsIoy0.pem\", \"x5c\": [\"MIIFoTCC" +
      "BImgAwIBAgIEWWwHrzANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJHQjEdMBsGA1UEChMUT3BlbiBCYW5raW5nIExpbWl0ZWQxETAPBgNVB" +
      "AsTCFRlc3QgUEtJMSUwIwYDVQQDExxPcGVuIEJhbmtpbmcgVGVzdCBJc3N1aW5nIENBMB4XDTE3MTIyNzEyNTcwNloXDTE4MTIyNzEzMjcwNl" +
      "owYDELMAkGA1UEBhMCR0IxHTAbBgNVBAoTFE9wZW4gQmFua2luZyBMaW1pdGVkMREwDwYDVQQLEwhUZXN0IFBLSTEfMB0GA1UEAxMWNmRpMkR" +
      "lODhzOEQyelZYZ3l4bTBiMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALfpw01GvAMttoxUlZ93Rtxc3Jm47+LXDKLzaKCIAd0n" +
      "jAH6R4Yylo+8hVYchlG0K5hKhaGQfAEdHxH1P3KZcdtksoUjG8AJTLLne3lxaWn/YadvLvjvbTaK7crhg/NXCDANbdnfFDjlt4co3xQaT4CJZ" +
      "uy5l3KPeYi7puGricFcGELtMRNl8+8W0cpXt/V4R1jiLwN/a3two+/1Qr5NX8rIWA61hVZ5TEjiQE6qjV8KMbGPSuiHwHIY9RCVPDdAjS4btQ" +
      "acoxzO6q6wz/phBOhSwFhKXuq87qUXKSFi5EaFKJde41VCzR36eTT4Ik8QT7BGcmyI558SPhNjoOFVyY8CAwEAAaOCAlswggJXMA4GA1UdDwE" +
      "B/wQEAwIHgDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwgeAGA1UdIASB2DCB1TCB0gYLKwYBBAGodYEGAWQwgcIwKgYIKwYB" +
      "BQUHAgEWHmh0dHA6Ly9vYi50cnVzdGlzLmNvbS9wb2xpY2llczCBkwYIKwYBBQUHAgIwgYYMgYNVc2Ugb2YgdGhpcyBDZXJ0aWZpY2F0ZSBjb" +
      "25zdGl0dXRlcyBhY2NlcHRhbmNlIG9mIHRoZSBPcGVuQmFua2luZyBSb290IENBIENlcnRpZmljYXRpb24gUG9saWNpZXMgYW5kIENlcnRpZm" +
      "ljYXRlIFByYWN0aWNlIFN0YXRlbWVudDA6BggrBgEFBQcBAQQuMCwwKgYIKwYBBQUHMAGGHmh0dHA6Ly9vYnRlc3QudHJ1c3Rpcy5jb20vb2N" +
      "zcDCBwwYDVR0fBIG7MIG4MDegNaAzhjFodHRwOi8vb2J0ZXN0LnRydXN0aXMuY29tL3BraS9vYnRlc3Rpc3N1aW5nY2EuY3JsMH2ge6B5pHcw" +
      "dTELMAkGA1UEBhMCR0IxHTAbBgNVBAoTFE9wZW4gQmFua2luZyBMaW1pdGVkMREwDwYDVQQLEwhUZXN0IFBLSTElMCMGA1UEAxMcT3BlbiBCY" +
      "W5raW5nIFRlc3QgSXNzdWluZyBDQTENMAsGA1UEAxMEQ1JMODAfBgNVHSMEGDAWgBQPAcAv6Ghs9yO/jmVuiQ3GpoV3tzAdBgNVHQ4EFgQUlE" +
      "i3t97ynfKhOYbFWNtcKIC0vbkwDQYJKoZIhvcNAQELBQADggEBAAqdNuOUgln2j1Ar1V1JyAe2B/2Fa5gMxAKxWJ4DC1bi6G0R9sArsCSswkO" +
      "u0Deo2g9uqKJS6FAaqghJEnmU4VOJ9+PZ85oJTrQAvxtQH3wJk/sJjKtE5Di4zOBLfyVGRosqlvVlqHtSGE5kf/ncrfRzBAyuf2szJHsoT4Oi" +
      "NB3lMcfSWPGVT86g9NpAEdJptW0SCqQ4X9EhSx59hNPngt2oHC//yZpbOcfdNV8PlyQREZ4wCNvUsM+9z6R7smfnVv+ILogXr9sgdEKzjUvJm" +
      "IBaS0QNbDyGR9519AYxKPuVhSc7Ik7gxAWcenQJml8B0nivERubRh4AUXSDanBXHB4=\"], \"use\": \"enc\"}]}"
    val run =
      for
        jwks <- decode[Id, JsonWebKeySet](jwksJson).eLiftET[IO]
        jsonWebKey1 <- jwks.keys.find(_.keyID.contains(KeyId("xl16BDxw57JN-3PtvrmyA-zWTgM"))).toRight(OptionEmpty)
          .eLiftET[IO]
        thumbprint1 <- EitherT(jsonWebKey1.calculateBase64UrlEncodedThumbprint[IO](`SHA-1`))
        jsonWebKey2 <- jwks.keys.find(_.keyID.contains(KeyId("2bag3Pig0ajRgDs8HLF0qNsIoy0"))).toRight(OptionEmpty)
          .eLiftET[IO]
        thumbprint2 <- EitherT(jsonWebKey2.calculateBase64UrlEncodedThumbprint[IO](`SHA-1`))
      yield
        thumbprint1.value == "xl16BDxw57JN-3PtvrmyA-zWTgM" && thumbprint2.value == "2bag3Pig0ajRgDs8HLF0qNsIoy0"
    run.value.asserting(value => assert(value.getOrElse(false)))
  }
end JsonWebKeyThumbprintFlatSpec
