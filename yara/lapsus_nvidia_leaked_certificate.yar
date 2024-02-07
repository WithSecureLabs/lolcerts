import "pe"

rule leaked_lapsus_nvidia_leaked_certificate {
   meta:
      status = "revoked"
      source = "leaked"
      description = "Leaked NVIDIA certificate utilised by LAPSUS."
      references = "https://www.malwarebytes.com/blog/news/2022/03/stolen-nvidia-certificates-used-to-sign-malware-heres-what-to-do"
      date = "31-08-2023"
      author = "Florian Roth"
      
   condition:
      uint16(0) == 0x5a4d and pe.timestamp > 1646092800 and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "VeriSign Class 3 Code Signing 2010 CA" and
         pe.signatures[i].serial == "43:bb:43:7d:60:98:66:28:6d:d8:39:e1:d0:03:09:f5" or "14:78:1b:c8:62:e8:dc:50:3a:55:93:46:f5:dc:c5:18"
      )
}