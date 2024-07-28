$publicfolder = get-childitem $PSScriptRoot\Public
foreach($file in $publicfolder){
    . $file.FullName
}