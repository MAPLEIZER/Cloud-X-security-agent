function Show-Banner {
    # Cloud-X Security ASCII Art Welcome Banner
    Write-Host "" -ForegroundColor Blue
   
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                               @@@@@                                                ' -ForegroundColor Blue
    Write-Host '                                            @@@      @@                                             ' -ForegroundColor Blue
    Write-Host '                                          @@             @@                                         ' -ForegroundColor Blue
    Write-Host '                                     @@@@@@         @@@@@@@@@@@                                     ' -ForegroundColor Blue
    Write-Host '                                    @@@           @@@         @@                                    ' -ForegroundColor Blue
    Write-Host '                                   @@           @@@  @@@@@@@@@ @@                                   ' -ForegroundColor Blue
    Write-Host '                                   @@ @       @@@  @@@       @ @@                                   ' -ForegroundColor Blue
    Write-Host '                                   @@ @@    @@@  @@@         @ @@                                   ' -ForegroundColor Blue
    Write-Host '                                    @@   @@    @@@            @@                                    ' -ForegroundColor Blue
    Write-Host '                                     @@@@@@@@@@@       @@@@@@@                                      ' -ForegroundColor Blue
    Write-Host '                                         @@@                                                        ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                    @@                     @@    @    @                             ' -ForegroundColor Blue
    Write-Host '                               @    @@   @@             @  @     @@  @                              ' -ForegroundColor Blue
    Write-Host '                             @@@@@@ @@ @@@@@@  @@  @@ @@@@@@       @@                               ' -ForegroundColor Blue
    Write-Host '                            @@      @@ @@   @@ @   @@ @    @      @ @@                              ' -ForegroundColor Blue
    Write-Host '                             @@@@@  @@ @@@@@@  @@@@@@ @@@@@@@    @   @@                             ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host '                                                                                                    ' -ForegroundColor Blue
    Write-Host ""
    Write-Host "                       CLOUD-X SECURITY WAZUH AGENT ENTERPRISE SETUP                         " -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "                              Version 3.1 - Enhanced Security                           " -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host "                                   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')                              " -ForegroundColor Yellow -BackgroundColor DarkGreen
    Write-Host "                                     by CLOUD-X SECURITY                                  " -ForegroundColor Cyan -BackgroundColor DarkGreen
    Write-Host ""
}

Export-ModuleMember -Function Show-Banner
