import "pe"

rule malicious_lamera_dprk_certificate {
   meta:
      status = "revoked"
      source = "malicious"
      description = "Certificate utilised to sign malware attributed to North Korea."
      references = "https://labs.withsecure.com/publications/no-pineapple-dprk-targeting-of-medical-research-and-technology-sector"
      date = "31-08-2023"
      author = "WithSecure"
      
   condition:
      uint16(0) == 0x5a4d and 
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "LAMERA CORPORATION LIMITED" and
         pe.signatures[i].serial == "87:9f:a9:42:f9:f0:97:b7:4f:d6:f7:da:bc:f1:74:5a"
      )
}