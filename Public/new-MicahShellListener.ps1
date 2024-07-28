function Start-MicahShellListener {
    param(
        [UInt64]$Port = 6969
    )
}
try {
    if($null -eq $port){
        $port = 6969
    }
    write-output $port
    $endpoint = new-object System.Net.IPEndPoint([ipaddress]::any,$port)
    $listener = new-object System.Net.Sockets.TcpListener $endpoint
    Write-Output "Socket made at $($endpoint.Address):$($endpoint.port)"
    return $listener
}
catch{}