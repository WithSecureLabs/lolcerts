import "pe"

rule malicious_hacking_team_malicious_certificate {
   meta:
      status = "expired"
      source = "malicious"
      description = "Certificate utilised by Hacking Team."
      references = "https://www.trendmicro.com/vinfo/fr/security/news/vulnerabilities-and-exploits/the-hacking-team-leak-zero-days-patches-and-more-zero-days"
      date = "15-11-2023"
      author = "WithSecure"
      
   condition:
      uint16(0) == 0x5a4d and 
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "VeriSign Class 3 Code Signing 2010 CA" and
         pe.signatures[i].serial == "0f:1b:43:48:4a:13:69:c8:30:38:dc:24:e7:77:8b:7d"
      )
}