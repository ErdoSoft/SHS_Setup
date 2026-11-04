# ==============================================================================
# SHS Launcher - 2-Factor Secure Cloud Installer
# Faktor 1: Live-Freigabe auf GitHub (Device Flow, isoliert auf SHS_Vault)
# Faktor 2: AES-256 + HMAC-SHA256 Installations-Passwort
# Copyright (c) Erdem Karayay
# One-Liner: irm https://erdosoft.github.io/shs.txt | iex
# ==============================================================================

function Invoke-SHSCloudInstaller {
    [CmdletBinding()]
    param(
        [string]$RepoOwner = "ErdoSoft",
        [string]$SetupRepo = "SHS_Setup",
        [string]$VaultRepo = "SHS_Vault",
        [string]$GitHubAppClientId = "Iv23liDSWRawUUJ3gcO9",
        [string]$TargetDir = "C:\SHS_Launcher",
        [string]$ExeName = "SHS_Launcher.exe",
        [string]$ManifestSource = "",
        [string]$PackageSource = "",
        [string]$TestPasswordPlain = "",
        [switch]$SkipDeviceFlow,
        [switch]$SkipAdminCheck,
        [switch]$SkipRegistryAdminFlag,
        [switch]$SkipTaskScheduler,
        [string]$AutoStartChoice = ""
    )

    $ErrorActionPreference = "Stop"

    # Unicode-Zeichen (7-Bit-ASCII-sicher fuer jede PowerShell-Version & irm | iex)
    $lowAe = [string][char]0x00E4
    $lowOe = [string][char]0x00F6
    $lowUe = [string][char]0x00FC
    $capAe = [string][char]0x00C4
    $capOe = [string][char]0x00D6
    $capUe = [string][char]0x00DC
    $ss    = [string][char]0x00DF
    $blkFull  = [string][char]0x2588
    $blkLight = [string][char]0x2591
    $chkMark  = [string][char]0x2713
    $copySym  = [string][char]0x00A9
    $tmSym    = [string][char]0x2122

    try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

    $scriptCloudUrl = "https://raw.githubusercontent.com/$RepoOwner/$SetupRepo/main/install.ps1"

    function Show-SHSBanner {
        try { Clear-Host } catch {}
        Write-Host ""
        Write-Host "  _____ ____  ____  _____ __  __   _  __    _    ____     _ __   __   _ __   __" -ForegroundColor Cyan
        Write-Host " | ____|  _ \|  _ \| ____|  \/  | | |/ /   / \  |  _ \   / \\ \ / /  / \\ \ / /" -ForegroundColor Cyan
        Write-Host " |  _| | |_) | | | |  _| | |\/| | | ' /   / _ \ | |_) | / _ \\ V /  / _ \\ V / " -ForegroundColor Cyan
        Write-Host " | |___|  _ <| |_| | |___| |  | | | . \  / ___ \|  _ < / ___ \| |  / ___ \| |  " -ForegroundColor DarkCyan
        Write-Host " |_____|_| \_\____/|_____|_|  |_| |_|\_\/_/   \_\_| \_/_/   \_\_| /_/   \_\_|  " -ForegroundColor DarkCyan
        Write-Host " ==============================================================================" -ForegroundColor DarkGray
        Write-Host "   SHS LAUNCHER  |  2FA SECURE CLOUD INSTALLER  |  ERDEM KARAYAY$tmSym" -ForegroundColor Yellow
        Write-Host " ==============================================================================" -ForegroundColor DarkGray
        Write-Host "   PC: $env:COMPUTERNAME   |   Benutzer: $env:USERNAME   |   Ziel: $(Join-Path $TargetDir $ExeName)" -ForegroundColor Gray
        Write-Host " ------------------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host ""
    }

    function Get-ProgressBarText {
        param([int]$Percent, [int]$Width = 26)
        if ($Percent -lt 0) { $Percent = 0 }
        if ($Percent -gt 100) { $Percent = 100 }
        $filled = [int][Math]::Round(($Percent / 100.0) * $Width)
        if ($filled -gt $Width) { $filled = $Width }
        $empty = $Width - $filled
        return "[" + ($blkFull * $filled) + ($blkLight * $empty) + ("] {0,3}%" -f $Percent)
    }

    function Write-OverallProgress {
        param([int]$StepNumber, [int]$TotalSteps, [int]$Percent, [string]$Title)
        $bar = Get-ProgressBarText -Percent $Percent -Width 24
        Write-Host ""
        Write-Host ("  Gesamtfortschritt: {0}  |  Schritt {1}/{2}: {3}" -f $bar, $StepNumber, $TotalSteps, $Title) -ForegroundColor Cyan
    }

    function Write-StepDone {
        param([string]$Message)
        Write-Host ("  [{0}] {1}" -f $chkMark, $Message) -ForegroundColor Green
    }

    function Write-StepInfo {
        param([string]$Message)
        Write-Host ("  [i] {0}" -f $Message) -ForegroundColor Gray
    }

    function Write-StepWarn {
        param([string]$Message)
        Write-Host ("  [!] {0}" -f $Message) -ForegroundColor Yellow
    }

    function ConvertFrom-SecureStringToUtf8Bytes {
        param([System.Security.SecureString]$SecureStr)
        $bstr = [IntPtr]::Zero
        try {
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureStr)
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($bstr)
            [byte[]]$utf8 = [System.Text.Encoding]::UTF8.GetBytes($plain)
            return ,$utf8
        } finally {
            if ($bstr -ne [IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
    }

    function Test-ConstantTimeEquals {
        param([byte[]]$A, [byte[]]$B)
        if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }
        $diff = 0
        for ($i = 0; $i -lt $A.Length; $i++) {
            $diff = $diff -bor ($A[$i] -bxor $B[$i])
        }
        return ($diff -eq 0)
    }

    function Resolve-VaultKeysFromPassword {
        param([byte[]]$PassBytes, [byte[]]$Salt, [byte[]]$ExpectedVerifier)
        $candidates = New-Object System.Collections.Generic.List[byte[]]
        $candidates.Add([byte[]]$PassBytes)
        # Abwaertskompatibilitaet fuer Pakete aus frueherem PowerShell-Array-Unrolling
        [byte[]]$legacyJoined = [System.Text.Encoding]::ASCII.GetBytes(($PassBytes -join " "))
        $candidates.Add($legacyJoined)

        try {
            foreach ($cand in $candidates) {
                $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(([byte[]]$cand), ([byte[]]$Salt), 150000)
                try {
                    $dk = $kdf.GetBytes(96)
                    [byte[]]$authCandidateKey = [byte[]]$dk[64..95]
                    $sha = [System.Security.Cryptography.SHA256]::Create()
                    try {
                        $candidateVerifier = $sha.ComputeHash($authCandidateKey)
                    } finally {
                        $sha.Dispose()
                        [Array]::Clear($authCandidateKey, 0, $authCandidateKey.Length)
                    }

                    if (Test-ConstantTimeEquals -A $candidateVerifier -B $ExpectedVerifier) {
                        [byte[]]$aesK  = [byte[]]$dk[0..31]
                        [byte[]]$hmacK = [byte[]]$dk[32..63]
                        [Array]::Clear($dk, 0, $dk.Length)
                        return @{
                            Matched = $true
                            AesKey  = $aesK
                            HmacKey = $hmacK
                        }
                    }
                    [Array]::Clear($dk, 0, $dk.Length)
                } finally {
                    if ($null -ne $kdf -and $kdf -is [System.IDisposable]) { $kdf.Dispose() }
                }
            }
            return @{ Matched = $false }
        } finally {
            if ($null -ne $legacyJoined -and $legacyJoined.Length -gt 0) {
                [Array]::Clear($legacyJoined, 0, $legacyJoined.Length)
            }
        }
    }

    function Get-AllScheduledTasksRecursive {
        param($Folder)
        $result = @()
        try {
            foreach ($t in $Folder.GetTasks(1)) {
                $result += $t
            }
            foreach ($sub in $Folder.GetFolders(0)) {
                $result += Get-AllScheduledTasksRecursive -Folder $sub
            }
        } catch {}
        return $result
    }

    function Resolve-PrivateAssetDownloadUrl {
        param([string]$AssetApiUrl, [string]$BearerToken)
        $req = [System.Net.HttpWebRequest]::Create($AssetApiUrl)
        $req.Method = "GET"
        $req.Accept = "application/octet-stream"
        $req.UserAgent = "SHS-Cloud-Installer/2.0"
        $req.Headers.Add("Authorization", "Bearer $BearerToken")
        $req.Headers.Add("X-GitHub-Api-Version", "2022-11-28")
        $req.AllowAutoRedirect = $false
        $req.Timeout = 30000

        try {
            $resp = $req.GetResponse()
            try {
                $loc = $resp.Headers["Location"]
                if (-not [string]::IsNullOrWhiteSpace($loc)) { return $loc }
            } finally {
                $resp.Close()
            }
        } catch [System.Net.WebException] {
            if ($null -ne $_.Exception.Response) {
                $loc = $_.Exception.Response.Headers["Location"]
                $_.Exception.Response.Close()
                if (-not [string]::IsNullOrWhiteSpace($loc)) { return $loc }
            }
            throw
        }
        throw "Konnte signierte Download-URL nicht aus GitHub-Tresor abrufen."
    }

    Show-SHSBanner

    $ephemeralDeviceToken = $null
    try {
        # ======================================================================
        # SCHRITT 1/7: ADMINISTRATOR-RECHTE PRUEFEN
        # ======================================================================
        Write-OverallProgress -StepNumber 1 -TotalSteps 7 -Percent 5 -Title "Administrator-Rechte pr$($lowUe)fen"

        if (-not $SkipAdminCheck) {
            $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
            $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

            if (-not $isAdmin) {
                Write-StepWarn "Keine Administrator-Rechte erkannt. Starte automatisch als Administrator neu..."
                Start-Sleep -Seconds 1
                if (-not [string]::IsNullOrWhiteSpace($PSCommandPath) -and (Test-Path $PSCommandPath)) {
                    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
                } else {
                    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"irm '$scriptCloudUrl' | iex`""
                }
                return
            }
        }
        Write-StepDone "Administrator-Berechtigung aktiv."

        # ======================================================================
        # SCHRITT 2/7: FAKTOR 1 - GITHUB LIVE-FREIGABE (DEVICE FLOW, NUR RAM)
        # ======================================================================
        Write-OverallProgress -StepNumber 2 -TotalSteps 7 -Percent 16 -Title "Faktor 1/2: Live-Freigabe auf GitHub anfordern"

        if (-not $SkipDeviceFlow) {
            if ([string]::IsNullOrWhiteSpace($GitHubAppClientId) -or $GitHubAppClientId -like "*__SHS_GITHUB_APP*") {
                Write-Host ""
                Write-Host "  [X] GitHub-App Client ID ist noch nicht konfiguriert." -ForegroundColor Red
                Write-Host "      Bitte zuerst einmalig Update_auf_GitHub_hochladen.bat auf dem Entwickler-PC ausf$($lowUe)hren." -ForegroundColor Yellow
                return
            }

            $dcHeaders = @{
                "Accept"     = "application/json"
                "User-Agent" = "SHS-Cloud-Installer/2.0"
            }
            $dcBody = "client_id=" + [Uri]::EscapeDataString($GitHubAppClientId)
            $dcResp = Invoke-WebRequest -Method Post -Uri "https://github.com/login/device/code" -Headers $dcHeaders -Body $dcBody -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -TimeoutSec 20
            $dcText = if ($dcResp.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($dcResp.Content) } else { [string]$dcResp.Content }
            $dcJson = $dcText | ConvertFrom-Json

            if ([string]::IsNullOrWhiteSpace($dcJson.user_code) -or [string]::IsNullOrWhiteSpace($dcJson.device_code)) {
                throw "GitHub Device-Flow konnte nicht gestartet werden: $dcText"
            }

            $userCode   = $dcJson.user_code
            $deviceCode = $dcJson.device_code
            $verifyUri  = if (-not [string]::IsNullOrWhiteSpace($dcJson.verification_uri)) { $dcJson.verification_uri } else { "https://github.com/login/device" }
            $pollSec    = if ($dcJson.interval -gt 0) { [int]$dcJson.interval } else { 5 }
            $expiresSec = if ($dcJson.expires_in -gt 0) { [int]$dcJson.expires_in } else { 900 }

            Write-Host ""
            Write-Host "  +--------------------------------------------------------------------------+" -ForegroundColor Yellow
            Write-Host "  |  [FAKTOR 1/2] LIVE-FREIGABE DURCH ADMINISTRATOR ERFORDERLICH             |" -ForegroundColor Yellow
            Write-Host "  +--------------------------------------------------------------------------+" -ForegroundColor Yellow
            Write-Host ("  |  Anfragender PC:   {0,-54}|" -f "$env:COMPUTERNAME ($env:USERNAME)") -ForegroundColor White
            Write-Host ("  |  1. Am Handy/PC $($lowOe)ffnen:   {0,-47}|" -f $verifyUri) -ForegroundColor Cyan
            Write-Host ("  |  2. Freigabe-Code:        >>>>   {0}   <<<<                         |" -f $userCode) -ForegroundColor Green
            Write-Host "  +--------------------------------------------------------------------------+" -ForegroundColor Yellow
            Write-Host "  [i] Dieser PC wird NICHT in GitHub eingeloggt (kein Browser, keine Speicherung)." -ForegroundColor Gray
            Write-Host ""

            $deadline = (Get-Date).AddSeconds($expiresSec)
            $spinChars = @("|", "/", "-", "\")
            $spinIdx = 0

            while ((Get-Date) -lt $deadline) {
                $remain = [Math]::Max(0, [int]($deadline - (Get-Date)).TotalSeconds)
                $remMin = [int][Math]::Floor($remain / 60)
                $remSec = $remain % 60
                $sc = $spinChars[$spinIdx % $spinChars.Length]
                $spinIdx++
                Write-Host ("`r  [{0}] Warte auf Freigabe von Code {1} auf GitHub (noch {2:00}:{3:00} Min.)...   " -f $sc, $userCode, $remMin, $remSec) -NoNewline -ForegroundColor Yellow

                Start-Sleep -Seconds $pollSec

                $tokBody = "client_id=" + [Uri]::EscapeDataString($GitHubAppClientId) +
                           "&device_code=" + [Uri]::EscapeDataString($deviceCode) +
                           "&grant_type=" + [Uri]::EscapeDataString("urn:ietf:params:oauth:grant-type:device_code")

                $tokResp = Invoke-WebRequest -Method Post -Uri "https://github.com/login/oauth/access_token" -Headers $dcHeaders -Body $tokBody -ContentType "application/x-www-form-urlencoded" -UseBasicParsing -TimeoutSec 20
                $tokText = if ($tokResp.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($tokResp.Content) } else { [string]$tokResp.Content }
                $tokJson = $tokText | ConvertFrom-Json

                if (-not [string]::IsNullOrWhiteSpace($tokJson.access_token)) {
                    $ephemeralDeviceToken = [string]$tokJson.access_token
                    Write-Host ""
                    break
                }

                if ($tokJson.error -eq "authorization_pending") {
                    continue
                } elseif ($tokJson.error -eq "slow_down") {
                    $pollSec += 5
                    continue
                } elseif ($tokJson.error -eq "access_denied") {
                    Write-Host ""
                    Write-Host "  [ABBRUCH] Die Anfrage wurde auf GitHub abgelehnt." -ForegroundColor Red
                    return
                } elseif ($tokJson.error -eq "expired_token") {
                    Write-Host ""
                    Write-Host "  [ABBRUCH] Der Freigabe-Code ist abgelaufen." -ForegroundColor Red
                    return
                } else {
                    Write-Host ""
                    throw "GitHub Freigabe-Fehler: $($tokJson.error_description) ($($tokJson.error))"
                }
            }

            if ([string]::IsNullOrWhiteSpace($ephemeralDeviceToken)) {
                Write-Host ""
                Write-Host "  [ABBRUCH] Zeit$($lowUe)berschreitung bei der GitHub-Freigabe." -ForegroundColor Red
                return
            }

            Write-StepDone "GitHub Live-Freigabe erteilt (Einmal-Leseberechtigung nur im Arbeitsspeicher)."
        } else {
            Write-StepInfo "Lokaler Testmodus: Device-Flow $($lowUe)bersprungen."
        }

        # ======================================================================
        # SCHRITT 3/7: FAKTOR 2 - TRESOR-METADATEN & INSTALLATIONS-PASSWORT
        # ======================================================================
        Write-OverallProgress -StepNumber 3 -TotalSteps 7 -Percent 30 -Title "Faktor 2/2: Installations-Passwort pr$($lowUe)fen"

        $manifest = $null
        try {
            if (-not [string]::IsNullOrWhiteSpace($ManifestSource)) {
                $manifest = (Get-Content -Path $ManifestSource -Raw -Encoding UTF8) | ConvertFrom-Json
            } else {
                $vaultManifestApi = "https://api.github.com/repos/$RepoOwner/$VaultRepo/contents/version.json"
                $mHeaders = @{
                    "Authorization"        = "Bearer $ephemeralDeviceToken"
                    "Accept"               = "application/vnd.github.raw+json"
                    "User-Agent"           = "SHS-Cloud-Installer/2.0"
                    "X-GitHub-Api-Version" = "2022-11-28"
                    "Cache-Control"        = "no-cache"
                }
                $mResp = Invoke-WebRequest -Method Get -Uri $vaultManifestApi -Headers $mHeaders -UseBasicParsing -TimeoutSec 20
                $mJson = if ($mResp.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($mResp.Content) } else { [string]$mResp.Content }
                $manifest = $mJson | ConvertFrom-Json
            }
        } catch {
            Write-Host ""
            Write-Host "  [X] Zugriff auf den privaten Tresor ($RepoOwner/$VaultRepo) fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "      Pr$($lowUe)fe, ob die GitHub-App f$($lowUe)r '$VaultRepo' (Contents: Read-only) installiert ist." -ForegroundColor Yellow
            return
        }

        $pkgVersion       = $manifest.Version
        $pkgDate          = $manifest.BuildDate
        $pkgSizeMB        = $manifest.SizeMB
        $manifestSalt     = [Convert]::FromBase64String($manifest.SaltBase64)
        $expectedVerifier = [Convert]::FromBase64String($manifest.AuthVerifierBase64)

        Write-StepInfo "Tresor-Paket: $pkgVersion  (Stand: $pkgDate | Gr$($lowOe)$($ss)e: $pkgSizeMB MB | AES-256)"

        $derivedAesKey  = $null
        $derivedHmacKey = $null
        $passAuthenticated = $false

        for ($attempt = 1; $attempt -le 3; $attempt++) {
            [byte[]]$passBytes = $null
            try {
                if (-not [string]::IsNullOrWhiteSpace($TestPasswordPlain)) {
                    [byte[]]$passBytes = [System.Text.Encoding]::UTF8.GetBytes($TestPasswordPlain)
                } else {
                    Write-Host ""
                    $secPass = Read-Host "  [?] [FAKTOR 2/2] Bitte Installations-Passwort eingeben (Versuch $attempt/3)" -AsSecureString
                    [byte[]]$passBytes = ConvertFrom-SecureStringToUtf8Bytes -SecureStr $secPass
                }

                if ($null -eq $passBytes -or $passBytes.Length -eq 0) {
                    Write-StepWarn "Das Passwort darf nicht leer sein."
                    if (-not [string]::IsNullOrWhiteSpace($TestPasswordPlain)) { break }
                    continue
                }

                $kdfResult = Resolve-VaultKeysFromPassword -PassBytes $passBytes -Salt $manifestSalt -ExpectedVerifier $expectedVerifier

                if ($kdfResult.Matched) {
                    $derivedAesKey  = [byte[]]$kdfResult.AesKey
                    $derivedHmacKey = [byte[]]$kdfResult.HmacKey
                    $passAuthenticated = $true
                    break
                } else {
                    Write-Host "  [X] Zugriff verweigert: Falsches Passwort!" -ForegroundColor Red
                    if (-not [string]::IsNullOrWhiteSpace($TestPasswordPlain)) { break }
                }
            } finally {
                if ($null -ne $passBytes -and $passBytes.Length -gt 0) {
                    [Array]::Clear($passBytes, 0, $passBytes.Length)
                }
            }
        }

        if (-not $passAuthenticated) {
            Write-Host ""
            Write-Host "  [ABBRUCH] Installation abgebrochen - Passwort ung$($lowUe)ltig." -ForegroundColor Red
            return
        }
        Write-StepDone "Beide Sicherheitsfaktoren best$($lowAe)tigt - AES-256 Schl$($lowUe)ssel bereit."

        # ======================================================================
        # SCHRITT 4/7: TRESOR-DOWNLOAD, TOKEN VERNICHTEN & AES-256 ENTSCHLUESSELUNG
        # ======================================================================
        Write-OverallProgress -StepNumber 4 -TotalSteps 7 -Percent 50 -Title "Tresor-Download & AES-256 Entschl$($lowUe)sselung"

        $tempId = [Guid]::NewGuid().ToString("N").Substring(0, 8)
        $tempEncFile = Join-Path $env:TEMP "SHS_Launcher_$tempId.enc"
        $tempStageExe = Join-Path $env:TEMP "SHS_Launcher_stage_$tempId.exe"

        try {
            $signedDownloadUrl = ""
            if (-not [string]::IsNullOrWhiteSpace($PackageSource)) {
                $signedDownloadUrl = $PackageSource
            } elseif (-not [string]::IsNullOrWhiteSpace($manifest.AssetApiUrl) -and -not [string]::IsNullOrWhiteSpace($ephemeralDeviceToken)) {
                $signedDownloadUrl = Resolve-PrivateAssetDownloadUrl -AssetApiUrl $manifest.AssetApiUrl -BearerToken $ephemeralDeviceToken
            } else {
                $signedDownloadUrl = $manifest.DownloadUrl
            }

            # SOFORT nach Abruf der einmaligen CDN-Download-URL das GitHub-RAM-Token vernichten!
            $ephemeralDeviceToken = $null

            if ($signedDownloadUrl -match '^https?://') {
                $req = [System.Net.HttpWebRequest]::Create($signedDownloadUrl)
                $req.Method = "GET"
                $req.AllowAutoRedirect = $true
                $req.UserAgent = "SHS-Cloud-Installer/2.0"
                $req.Timeout = 60000
                $req.ReadWriteTimeout = 60000

                $webResp = $req.GetResponse()
                try {
                    $totalBytes = $webResp.ContentLength
                    $respStream = $webResp.GetResponseStream()
                    $outEncStream = New-Object System.IO.FileStream($tempEncFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                    try {
                        $buffer = New-Object byte[] 65536
                        $downloaded = [long]0
                        $sw = [System.Diagnostics.Stopwatch]::StartNew()
                        $lastUiMs = [long]-500

                        while (($read = $respStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                            $outEncStream.Write($buffer, 0, $read)
                            $downloaded += $read

                            if (($sw.ElapsedMilliseconds - $lastUiMs) -ge 120 -or ($totalBytes -gt 0 -and $downloaded -eq $totalBytes)) {
                                $lastUiMs = $sw.ElapsedMilliseconds
                                $dlMB = $downloaded / 1MB
                                $sec = [Math]::Max(0.1, $sw.Elapsed.TotalSeconds)
                                $speedMB = $dlMB / $sec
                                if ($totalBytes -gt 0) {
                                    $pct = [int][Math]::Round(($downloaded * 100.0) / $totalBytes)
                                    $totMB = $totalBytes / 1MB
                                    $dlBar = Get-ProgressBarText -Percent $pct -Width 24
                                    Write-Host ("`r  [>>] Download: {0}  ({1:N1} / {2:N1} MB | {3:N1} MB/s)   " -f $dlBar, $dlMB, $totMB, $speedMB) -NoNewline -ForegroundColor Yellow
                                } else {
                                    Write-Host ("`r  [>>] Download: {0:N1} MB ({1:N1} MB/s)   " -f $dlMB, $speedMB) -NoNewline -ForegroundColor Yellow
                                }
                            }
                        }
                        Write-Host ""
                    } finally {
                        $outEncStream.Dispose()
                        $respStream.Dispose()
                    }
                } finally {
                    $webResp.Close()
                }
            } else {
                Copy-Item -Path $signedDownloadUrl -Destination $tempEncFile -Force
            }

            Write-StepDone "Verschl$($lowUe)sseltes Paket geladen (RAM-Token gel$($lowOe)scht)."

            # --- HMAC-SHA256 Integritaetspruefung + AES-256-CBC Entschluesselung ---
            $encFs = New-Object System.IO.FileStream($tempEncFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                if ($encFs.Length -lt 88) {
                    throw "Ung$($lowUe)ltige Paketgr$($lowOe)$($ss)e ($($encFs.Length) Bytes)."
                }

                $header72 = New-Object byte[] 72
                $hdrRead = 0
                while ($hdrRead -lt 72) {
                    $r = $encFs.Read($header72, $hdrRead, 72 - $hdrRead)
                    if ($r -le 0) { throw "Unerwartetes Dateiende im Header." }
                    $hdrRead += $r
                }

                $magicStr = [System.Text.Encoding]::ASCII.GetString($header72, 0, 8)
                if ($magicStr -ne "SHSENC01") {
                    throw "Ung$($lowUe)ltiges Paketformat ($magicStr)."
                }

                $fileSalt     = [byte[]]$header72[8..23]
                $fileIv       = [byte[]]$header72[24..39]
                $expectedHmac = [byte[]]$header72[40..71]

                if (-not (Test-ConstantTimeEquals -A $fileSalt -B $manifestSalt)) {
                    throw "Salt-Abweichung zwischen Manifest und Paket erkannt."
                }

                $hmac = New-Object System.Security.Cryptography.HMACSHA256
                try {
                    $hmac.Key = $derivedHmacKey
                    $null = $hmac.TransformBlock($header72, 0, 40, $null, 0)

                    $encFs.Position = 72
                    $buf = New-Object byte[] 65536
                    while (($r = $encFs.Read($buf, 0, $buf.Length)) -gt 0) {
                        $null = $hmac.TransformBlock($buf, 0, $r, $null, 0)
                    }
                    $emptyBytes = New-Object byte[] 0
                    $null = $hmac.TransformFinalBlock($emptyBytes, 0, 0)
                    $actualHmac = $hmac.Hash
                } finally {
                    $hmac.Dispose()
                }

                if (-not (Test-ConstantTimeEquals -A $actualHmac -B $expectedHmac)) {
                    throw "Kryptografische HMAC-SHA256 Signaturpr$($lowUe)fung fehlgeschlagen!"
                }
                Write-StepDone "HMAC-SHA256 Signaturpr$($lowUe)fung bestanden (Paket unver$($lowAe)ndert & authentisch)."

                $cipherTotal = $encFs.Length - 72
                $encFs.Position = 72

                $aes = [System.Security.Cryptography.Aes]::Create()
                try {
                    $aes.KeySize = 256
                    $aes.BlockSize = 128
                    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
                    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                    $aes.Key = $derivedAesKey
                    $aes.IV  = $fileIv

                    $decryptor = $aes.CreateDecryptor()
                    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($encFs, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
                    $stageOut = New-Object System.IO.FileStream($tempStageExe, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                    try {
                        $decBuf = New-Object byte[] 65536
                        $written = [long]0
                        $lastDecUi = [long]-500
                        $swDec = [System.Diagnostics.Stopwatch]::StartNew()

                        while (($r = $cryptoStream.Read($decBuf, 0, $decBuf.Length)) -gt 0) {
                            $stageOut.Write($decBuf, 0, $r)
                            $written += $r
                            if (($swDec.ElapsedMilliseconds - $lastDecUi) -ge 120) {
                                $lastDecUi = $swDec.ElapsedMilliseconds
                                $pctDec = [int][Math]::Min(99, [Math]::Round(($written * 100.0) / [Math]::Max(1, $cipherTotal)))
                                $decBar = Get-ProgressBarText -Percent $pctDec -Width 24
                                Write-Host ("`r  [>>] AES-256 Entschl$($lowUe)sselung: {0}   " -f $decBar) -NoNewline -ForegroundColor Yellow
                            }
                        }
                        $decBarDone = Get-ProgressBarText -Percent 100 -Width 24
                        Write-Host ("`r  [>>] AES-256 Entschl$($lowUe)sselung: {0}   " -f $decBarDone) -ForegroundColor Yellow
                    } finally {
                        $stageOut.Dispose()
                        $cryptoStream.Dispose()
                        $decryptor.Dispose()
                    }
                } finally {
                    $aes.Dispose()
                }
            } finally {
                $encFs.Dispose()
            }

            $peCheck = New-Object byte[] 2
            $peFs = [System.IO.File]::OpenRead($tempStageExe)
            try {
                $null = $peFs.Read($peCheck, 0, 2)
            } finally {
                $peFs.Dispose()
            }
            if ($peCheck[0] -ne 0x4D -or $peCheck[1] -ne 0x5A) {
                throw "Entschl$($lowUe)sselte Datei ist keine g$($lowUe)ltige Windows-EXE (MZ-Header fehlt)."
            }
            Write-StepDone "EXE erfolgreich entschl$($lowUe)sselt & gepr$($lowUe)ft."
        } finally {
            if (Test-Path $tempEncFile) {
                Remove-Item -Path $tempEncFile -Force -ErrorAction SilentlyContinue
            }
            if ($null -ne $derivedAesKey)  { [Array]::Clear($derivedAesKey, 0, $derivedAesKey.Length) }
            if ($null -ne $derivedHmacKey) { [Array]::Clear($derivedHmacKey, 0, $derivedHmacKey.Length) }
        }

        # ======================================================================
        # SCHRITT 5/7: ALTE VERSION STOPPEN & IN C:\SHS_Launcher AUSTAUSCHEN
        # ======================================================================
        Write-OverallProgress -StepNumber 5 -TotalSteps 7 -Percent 72 -Title "Zielordner $TargetDir aktualisieren"

        $finalExePath = Join-Path $TargetDir $ExeName
        $oldTaskExePaths = @()
        $matchingTasks = @()
        $schedService = $null

        if (-not $SkipTaskScheduler) {
            try {
                $schedService = New-Object -ComObject "Schedule.Service"
                $schedService.Connect()
                $allTasks = Get-AllScheduledTasksRecursive -Folder $schedService.GetFolder("\")
                foreach ($t in $allTasks) {
                    if ($t.Name -match 'SHS[_ ]?Launcher' -or $t.Xml -match 'SHS[_ ]?Launcher') {
                        $matchingTasks += $t
                        try {
                            foreach ($act in $t.Definition.Actions) {
                                if ($act.Type -eq 0 -and -not [string]::IsNullOrWhiteSpace($act.Path)) {
                                    $cleanOld = $act.Path.Trim().Trim('"')
                                    $cleanOld = [Environment]::ExpandEnvironmentVariables($cleanOld)
                                    if (-not [string]::IsNullOrWhiteSpace($cleanOld)) {
                                        $oldTaskExePaths += $cleanOld
                                    }
                                }
                            }
                        } catch {}
                    }
                }
            } catch {}
        }

        $stoppedAny = $false
        $runningProcs = @(Get-Process -ErrorAction SilentlyContinue)
        foreach ($proc in $runningProcs) {
            if ($proc.Id -eq $PID) { continue }
            $shouldStop = $false
            $procPath = ""
            try { $procPath = $proc.MainModule.FileName } catch {}

            if ($proc.ProcessName -match '^SHS[_ ]?Launcher') {
                $shouldStop = $true
            } elseif (-not [string]::IsNullOrWhiteSpace($procPath)) {
                if ($procPath -ieq $finalExePath) { $shouldStop = $true }
                foreach ($op in $oldTaskExePaths) {
                    if ($procPath -ieq $op) { $shouldStop = $true }
                }
                if ($procPath.StartsWith($TargetDir, [System.StringComparison]::OrdinalIgnoreCase) -and $proc.ProcessName -match 'SHS') {
                    $shouldStop = $true
                }
            }

            if ($shouldStop) {
                Write-StepInfo "Beende laufende Instanz: $($proc.ProcessName) (PID $($proc.Id))..."
                try {
                    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                    $stoppedAny = $true
                } catch {}
            }
        }

        if ($stoppedAny) {
            Start-Sleep -Milliseconds 1200
            try {
                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -ErrorAction SilentlyContinue
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoRestartShell" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            } catch {}
            Write-StepDone "Laufende Vorg$($lowAe)ngerversion sauber beendet."
        }

        if (-not (Test-Path $TargetDir)) {
            $null = New-Item -ItemType Directory -Path $TargetDir -Force
            Write-StepDone "Zielordner neu angelegt: $TargetDir"
        }

        $targetConfigPath = Join-Path $TargetDir "config.dat"
        if (-not (Test-Path $targetConfigPath)) {
            foreach ($op in $oldTaskExePaths) {
                $oldDir = Split-Path -Path $op -Parent -ErrorAction SilentlyContinue
                if (-not [string]::IsNullOrWhiteSpace($oldDir)) {
                    $oldCfg = Join-Path $oldDir "config.dat"
                    if ((Test-Path $oldCfg) -and ($oldCfg -ine $targetConfigPath)) {
                        Copy-Item -Path $oldCfg -Destination $targetConfigPath -Force
                        Write-StepDone "Bestehende config.dat aus '$oldDir' automatisch $($lowUe)bernommen."
                        break
                    }
                }
            }
        } else {
            Write-StepInfo "Vorhandene Einstellungen ($targetConfigPath) bleiben unver$($lowAe)ndert erhalten."
        }

        $backupDir = Join-Path $TargetDir "_Backup"
        $stamp = Get-Date -Format "yyyyMMdd_HHmmss"

        if (Test-Path $finalExePath) {
            if (-not (Test-Path $backupDir)) { $null = New-Item -ItemType Directory -Path $backupDir -Force }
            $bakTarget = Join-Path $backupDir ("SHS_Launcher_" + $stamp + ".exe.bak")
            for ($retry = 1; $retry -le 10; $retry++) {
                try {
                    Move-Item -Path $finalExePath -Destination $bakTarget -Force
                    break
                } catch {
                    if ($retry -eq 10) { throw "Alte Datei '$finalExePath' ist noch gesperrt: $($_.Exception.Message)" }
                    Start-Sleep -Milliseconds 500
                }
            }
            Write-StepDone "Alte SHS_Launcher.exe gesichert & ausgetauscht."
        }

        foreach ($op in ($oldTaskExePaths | Select-Object -Unique)) {
            if ((Test-Path $op) -and ($op -ine $finalExePath)) {
                $opParent = Split-Path -Path $op -Parent
                if ($opParent -ieq $TargetDir) {
                    if (-not (Test-Path $backupDir)) { $null = New-Item -ItemType Directory -Path $backupDir -Force }
                    $oldLeaf = Split-Path -Path $op -Leaf
                    $oldArchivePath = Join-Path $backupDir ($oldLeaf + "." + $stamp + ".bak")
                    try {
                        Move-Item -Path $op -Destination $oldArchivePath -Force
                        Write-StepDone "Alte Programmdatei '$oldLeaf' ins Backup verschoben."
                    } catch {}
                }
            }
        }

        if (Test-Path $backupDir) {
            $oldBaks = @(Get-ChildItem -Path $backupDir -Filter "*.bak" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
            if ($oldBaks.Count -gt 2) {
                foreach ($ob in $oldBaks[2..($oldBaks.Count - 1)]) {
                    Remove-Item -Path $ob.FullName -Force -ErrorAction SilentlyContinue
                }
            }
        }

        try {
            Move-Item -Path $tempStageExe -Destination $finalExePath -Force
            try { Unblock-File -Path $finalExePath -ErrorAction SilentlyContinue } catch {}
        } finally {
            if (Test-Path $tempStageExe) {
                Remove-Item -Path $tempStageExe -Force -ErrorAction SilentlyContinue
            }
        }
        Write-StepDone "Neue Programmversion bereitgestellt: $finalExePath"

        # ======================================================================
        # SCHRITT 6/7: IMMER ALS ADMINISTRATOR AUSFUEHREN (FUER JEDEN BENUTZER)
        # ======================================================================
        Write-OverallProgress -StepNumber 6 -TotalSteps 7 -Percent 86 -Title "Administrator-Modus f$($lowUe)r alle Benutzer aktivieren"

        if (-not $SkipRegistryAdminFlag) {
            $layersRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
            if (-not (Test-Path $layersRegPath)) {
                $null = New-Item -Path $layersRegPath -Force
            }
            Set-ItemProperty -Path $layersRegPath -Name $finalExePath -Value "~ RUNASADMIN" -Type String -Force

            $verifyReg = (Get-ItemProperty -Path $layersRegPath -Name $finalExePath -ErrorAction Stop).$finalExePath
            if ($verifyReg -ne "~ RUNASADMIN") {
                throw "Registry-Eintrag RUNASADMIN konnte nicht best$($lowAe)tigt werden."
            }
            Write-StepDone "Systemweiter Kompatibilit$($lowAe)tseintrag gesetzt (~ RUNASADMIN f$($lowUe)r alle Benutzer)."
        } else {
            Write-StepInfo "Registry-Schritt im Testmodus $($lowUe)bersprungen."
        }

        # ======================================================================
        # SCHRITT 7/7: WINDOWS AUFGABENPLANUNG ANPASSEN (ODER NEU ANLEGEN)
        # ======================================================================
        Write-OverallProgress -StepNumber 7 -TotalSteps 7 -Percent 96 -Title "Windows Aufgabenplanung konfigurieren"

        $configuredTaskNames = @()
        if (-not $SkipTaskScheduler) {
            if ($null -eq $schedService) {
                $schedService = New-Object -ComObject "Schedule.Service"
                $schedService.Connect()
            }

            $quotedExePath = '"' + $finalExePath + '"'

            if ($matchingTasks.Count -gt 0) {
                foreach ($taskItem in $matchingTasks) {
                    $tName = $taskItem.Name
                    $tPath = $taskItem.Path
                    $parentFolderPath = Split-Path -Path $tPath -Parent
                    if ([string]::IsNullOrWhiteSpace($parentFolderPath)) { $parentFolderPath = "\" }
                    $taskFolder = $schedService.GetFolder($parentFolderPath)

                    $def = $taskItem.Definition
                    $def.Actions.Clear()
                    $newAction = $def.Actions.Create(0)
                    $newAction.Path = $quotedExePath
                    $newAction.WorkingDirectory = $TargetDir
                    $def.Principal.RunLevel = 1

                    try {
                        $null = $taskFolder.RegisterTaskDefinition($tName, $def, 6, $def.Principal.UserId, $null, $def.Principal.LogonType)
                    } catch {
                        $def.Principal.LogonType = 3
                        $null = $taskFolder.RegisterTaskDefinition($tName, $def, 6, $def.Principal.UserId, $null, 3)
                    }

                    $configuredTaskNames += $tPath
                    Write-StepDone "Aufgabe '$tPath' aktualisiert -> $quotedExePath"
                }
            } else {
                $newTaskName = "SHS_Launcher_starten"
                $rootFolder = $schedService.GetFolder("\")
                $td = $schedService.NewTask(0)

                $currentUserFull = if (-not [string]::IsNullOrWhiteSpace($env:USERDOMAIN)) { "$env:USERDOMAIN\$env:USERNAME" } else { "$env:COMPUTERNAME\$env:USERNAME" }
                $td.RegistrationInfo.Author = $currentUserFull
                $td.Principal.UserId = $currentUserFull
                $td.Principal.LogonType = 3
                $td.Principal.RunLevel  = 1

                $trg = $td.Triggers.Create(9)
                $trg.Delay = "PT3S"
                $trg.Enabled = $true

                $act = $td.Actions.Create(0)
                $act.Path = $quotedExePath
                $act.WorkingDirectory = $TargetDir

                $td.Settings.DisallowStartIfOnBatteries = $false
                $td.Settings.StopIfGoingOnBatteries = $false
                $td.Settings.WakeToRun = $true
                $td.Settings.AllowDemandStart = $true
                $td.Settings.StartWhenAvailable = $true
                $td.Settings.RestartInterval = "PT1M"
                $td.Settings.RestartCount = 5
                $td.Settings.ExecutionTimeLimit = "PT0S"
                $td.Settings.AllowHardTerminate = $true
                $td.Settings.MultipleInstances = 1
                $td.Settings.Enabled = $true

                $null = $rootFolder.RegisterTaskDefinition($newTaskName, $td, 6, $currentUserFull, $null, 3)
                $configuredTaskNames += "\$newTaskName"
                Write-StepDone "Neue Aufgabe '\$newTaskName' exakt nach SHS-Standard angelegt."
            }
        } else {
            Write-StepInfo "Aufgabenplanung im Testmodus $($lowUe)bersprungen."
        }

        # ======================================================================
        # ABSCHLUSS (100%)
        # ======================================================================
        $bar100 = Get-ProgressBarText -Percent 100 -Width 24
        Write-Host ""
        Write-Host ("  Gesamtfortschritt: {0}  |  Installation abgeschlossen!" -f $bar100) -ForegroundColor Green
        Write-Host ""
        Write-Host "  +--------------------------------------------------------------------------+" -ForegroundColor Green
        Write-Host "  |  INSTALLATION ERFOLGREICH ABGESCHLOSSEN                                  |" -ForegroundColor Green
        Write-Host "  +--------------------------------------------------------------------------+" -ForegroundColor Green
        Write-Host ("  |  Version:          {0,-54}|" -f $pkgVersion) -ForegroundColor White
        $exeDisp = if ($finalExePath.Length -gt 54) { "..." + $finalExePath.Substring($finalExePath.Length - 51) } else { $finalExePath }
        Write-Host ("  |  Programmdatei:    {0,-54}|" -f $exeDisp) -ForegroundColor White
        Write-Host ("  |  Admin-Modus:      Immer als Administrator (alle Benutzer)               |") -ForegroundColor White
        $taskDisplay = if ($configuredTaskNames.Count -gt 0) { ($configuredTaskNames -join ", ") } else { "(Testmodus)" }
        if ($taskDisplay.Length -gt 54) { $taskDisplay = $taskDisplay.Substring(0, 51) + "..." }
        Write-Host ("  |  Aufgabenplanung:  {0,-54}|" -f $taskDisplay) -ForegroundColor White
        Write-Host ("  |  Sicherheit:       2-Faktor (GitHub Live-Freigabe + AES-256)             |") -ForegroundColor White
        Write-Host ("  |  Bereitgestellt:   {0,-54}|" -f ("Erdem Karayay" + $tmSym)) -ForegroundColor Yellow
        Write-Host "  +--------------------------------------------------------------------------+" -ForegroundColor Green
        Write-Host ""

        $choice = $AutoStartChoice
        if ([string]::IsNullOrWhiteSpace($choice)) {
            $choice = Read-Host "  [?] SHS Launcher jetzt sofort starten? [J/N]"
        }

        if ($choice -match '^[JjYy]') {
            Write-Host "  [>>] Starte $finalExePath ..." -ForegroundColor Cyan
            Start-Process -FilePath $finalExePath -WorkingDirectory $TargetDir -Verb RunAs
        } else {
            if (-not (Get-Process -Name "explorer" -ErrorAction SilentlyContinue)) {
                Start-Process -FilePath (Join-Path $env:WINDIR "explorer.exe")
            }
            Write-Host "  [OK] Fertig. Der SHS Launcher startet automatisch bei der n$($lowAe)chsten Anmeldung." -ForegroundColor Gray
        }
    } finally {
        $ephemeralDeviceToken = $null
    }
}

if ($env:SHS_SKIP_AUTORUN -ne "1") {
    Invoke-SHSCloudInstaller
}
