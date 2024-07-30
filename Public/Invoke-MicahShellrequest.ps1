Function invoke-MicahShellRequest { 
    param(
        [string]$EndPoint, 
        [uint64]$Port, 
        [string]$Message,
        [string]$action
    )
    if($null -eq $port){
        $port = 6969
    }
    $action_list = @{
        "GET" = "00"
        "POST" = "01"
    }
    $symetrickey = [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
    $UTF8 = [System.Text.Encoding]::UTF8
    #$IP = [System.Net.Dns]::GetHostAddresses($EndPoint) 
    $Socket = New-Object System.Net.Sockets.TCPClient($endpoint,$Port) 
    $data = $UTF8.GetBytes($Message)
    $data | Out-Null
    $Stream = $Socket.GetStream() 
    $Writer = New-Object System.IO.StreamWriter($Stream)
    $reader = new-object System.IO.StreamReader($stream)
    $pubkey = new-object system.byte[] 256
    $pubkeycert = $reader.Read($pubkey,0,$pubkey.Length)
    $encrypted_value = $pubkeycert.encrypt($symetrickey, "RSAencryptionpadding.OaepSHA1")
    $encrypted_value_splat = $encrypted_value -split '(..)' -ne ""
    $filestream = [System.IO.MemoryStream]::new()
    $hashstreamwriter = [System.IO.StreamWriter]::new($filestream)
    $hashstreamwriter.Write("$($encrypted_value)")
    $hashstreamwriter.flush()
    $filestream.Position = 0
    $hashvalue = Get-FileHash -InputStream $filestream | select-object Hash
    $first14bytesofhash = ("$hashvalue".substring(0,28)) -split '(..)' -ne ""
    $message_byte_array = new-object system.byte[] 1024
    $hashbytecounter = 0
    $encrypt_counter = 0
    $server_string = ""
    for($counter=0;$counter -lt $message_byte_array.Length; $counter++){
        if($counter -eq 0){
            $message_byte_array[$count] = 69
        }elseif(($counter -gt 0) -and ($counter -le 3)){
            $message_byte_array[$count] = 00
        }elseif(($counter =gt 3) -and ($counter =le 14)){
            $message_byte_array[$count] = $first14bytesofhash[$hashbytecounter]
            $hashbytecounter++
        }elseif ($counter -eq 15) {
            $message_byte_array[$count] = $action_list."$($action)"
        }elseif(($counter -gt 15) -and ($counter -le 100)){
            $message_byte_array[$count] = "00"
        }elseif(($counter -gt 100) -and ($counter -le 1024)){
            $message_byte_array[$count] = $encrypted_value_splat[$encrypt_counter]
            $encrypt_counter++
        }
    }
    $message_byte_array | ForEach-Object{
        $Writer.WriteLine($_)
        $Writer.Flush()
    }
    $responce_bytes = new-object system.byte[] 1024
    $responce = $reader.read($responce_bytes,0,$responce_bytes.Length)
    $responcebytecounter = 0
    foreach($repondedbytes in $responce){
        if($responcebytecounter -eq 0){
            if($repondedbytes -ne 69){
                write-error "Byte Header Doesn't Match Correctly to protocol spec"
            }
        }elseif(($responcebytecounter -gt 0) -and ($responcebytecounter -le 3)){
            $digit = [system.text.encoding]::UTF8.GetString($repondedbytes)
            switch($responcebytecounter){
                1{
                    switch($digit){
                        0{
                            write-error "Server has disapeared into the unknown"
                            $server_start = "Abnormal"
                        }
                        1{
                            Write-output "Server is OKAY"
                            $server_start = "Okay"
                        }
                        2{
                            Write-Warning "Server has Warning"
                            $server_start = "Warning"
                        }
                        3{
                            Write-Error "Server has error"
                            $server_start = "Error"
                        }
                        4{
                            Write-Output "Server is confused"
                            $server_start = "Confusion"
                        }
                    }
                }
                2{
                    switch($digit){
                        0{
                            write-output "COM object EVERYTHING"
                            $server_componet = "EVERYTHING"
                        }
                        1{
                            Write-output "COM object RECIVER"
                            $server_componet = "LISTENER"
                        }
                        2{
                            Write-output "COM object PARSER"
                            $server_componet = "PARSER"
                        }
                        3{
                            Write-Output "COM object SCUFFED TLS"
                            $server_componet = "TLS"
                        }
                        4{
                            Write-Output "COM object CERTIFICATE"
                            $server_componet = "CERTIFICATE"
                        }
                    }
                }
                3{
                    switch($digit){
                        0{
                            write-error "Server has disapeared into the unknown"
                            $server_start = "Abnormal"
                        }
                        1{
                            Write-output "Server is OKAY"
                            $server_start = "Okay"
                        }
                        2{
                            Write-Warning "Server has Warning"
                            $server_start = "Warning"
                        }
                        3{
                            Write-Error "Server has error"
                            $server_start = "Error"
                        }
                        4{
                            Write-Output "Server is confused"
                            $server_start = "Confusion"
                        }
                    }
                }
                default{Write-Output "Bug detected"}
            }
            $server_string = $server_start + "in" + $server_componet + "Caused By" + $thing_unhappy
        }
    }
    Write-Output "closing Socket Client Connection"
    $Stream.Close()
    $Socket.Close()
}