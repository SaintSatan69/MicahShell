Function invoke-MicahShellRequest { 
    param ( [ValidateNotNullOrEmpty()] 
        [string] $EndPoint, 
        [uint64] $Port, 
        [string]$Message,
        [string]$action
    ) 
    $symetrickey = [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
    $UTF8 = [System.Text.Encoding]::UTF8
    #$IP = [System.Net.Dns]::GetHostAddresses($EndPoint) 
    $Socket = New-Object System.Net.Sockets.TCPClient($endpoint,$Port) 
    $data = $UTF8.GetBytes($Message)
    $Stream = $Socket.GetStream() 
    $Writer = New-Object System.IO.StreamWriter($Stream)
    $reader = new-object System.IO.StreamReader($stream)
    $pubkey = new-object system.byte[] 256
    $pubkeycert = $reader.Read($pubkey,0,$pubkey.Length)
    $pubkeycert.encrypt($symetrickey, "RSAencryptionpadding.OaepSHA1")
    $Message | ForEach-Object{
        $Writer.WriteLine($_)
        $Writer.Flush()
    }
    $Stream.Close()
    $Socket.Close()
}