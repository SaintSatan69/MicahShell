function Invoke-MicahShellListener{
    [CmdletBinding()]
    param(
        [parameter(
            mandatory,
            valuefrompipeline=$true,
            Position=1
        )]
        [psobject]$ListenerObject,

        [parmeter(
            mandatory,
            valuefrompipeline=$true,
            Position=2
        )]
        [X509Certificate2]$certificatethumbprint
    )
    $cert = Get-ChildItem Cert:\LocalMachine\my | where-object {$_.Thumbprint -eq $certificatethumbprint}
    $certprivate = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $certpublic = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
    $listener = $ListenerObject
    $listener.start()
    Write-Output "Listener Starting"
    Start-sleep -Milliseconds 10
    $data = $listener.AcceptTcpClient()
    $bytes = new-object system.byte[] 1024
    $stream = $data.GetStream()
    $certpublic | foreach-object{
        $stream.Writeline($_)
        $stream.Flush()
    }
    $symetrickeybytes = new-object system.byte[] 256
    $symetrickeyencrypted = $stream.Read($symetrickeybytes,0,$symetrickeybytes.Length)
    $symetrickey = certprivate.decrypt($symetrickeyencrypted,"RSAencryptionpadding.OapsSHA1")
    while (($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){
        $EncodedText = New-Object System.Text.ASCIIEncoding
        $data = $EncodedText.GetString($bytes,0, $i)
    }
    return $data
}