/* Conservative triage rules. Matches are review cues, never confirmed findings. */
rule Embedded_Private_Key_Marker
{
    meta:
        purpose = "CHK-08 review cue"
    strings:
        $pem1 = "-----BEGIN PRIVATE KEY-----" ascii
        $pem2 = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $pem3 = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
    condition:
        any of them
}

rule Suspicious_Shell_Download_Chain
{
    meta:
        purpose = "CHK-09/CHK-17 review cue"
    strings:
        $shell1 = "/bin/sh" ascii
        $shell2 = "/bin/bash" ascii
        $download1 = "curl " ascii nocase
        $download2 = "wget " ascii nocase
    condition:
        any of ($shell*) and any of ($download*)
}
