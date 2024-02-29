import "pe"

rule leaked_anydesk_leaked_certificate {
   meta:
      status = "revoked"
      source = "leaked"
      description = "AnyDesk Revoked Certificates after public statement: https://anydesk.com/en/public-statement"
      references = "https://github.com/Neo23x0/signature-base/blob/master/yara/gen_anydesk_compromised_cert_feb23.yar"
      date = "07-02-2024"
      author = "Florian Roth"
      
   condition:
      uint16(0) == 0x5a4d and pe.timestamp > 1706486400 and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         pe.signatures[i].serial == "0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8"
      )
}