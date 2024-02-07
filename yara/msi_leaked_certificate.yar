import "pe"

rule leaked_msi_leaked_certificate {
   meta:
      status = "revoked"
      source = "leaked"
      description = "Leaked certificate from MicroStar International (MSI) driver package."
      references = "https://thehackernews.com/2023/05/msi-data-breach-private-code-signing.html"
      date = "31-08-2023"
      author = "WithSecure"
      
   condition:
      uint16(0) == 0x5a4d and 
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert SHA2 Assured ID Code Signing CA" and
         pe.signatures[i].serial == "0b:88:60:32:86:1d:95:53:c6:8f:80:33:13:a9:89:75"
      )
}