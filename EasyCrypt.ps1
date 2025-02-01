############################################################################
# EasyCrypt.ps1
#   - 複数公開鍵で暗号化/復号
#   - ダイアログがメイン画面に隠れないようオーナーフォーム指定
#   - 上書き確認時に、上書き対象ファイル名を表示するよう修正
############################################################################

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO

$global:rsabit = 4096
$global:keysFolder = Join-Path (Get-Location) "keys"
if (-not (Test-Path $global:keysFolder)) {
    New-Item -ItemType Directory -Path $global:keysFolder | Out-Null
}

#====================== (1) Show-MessageBoxWithTimeout =====================
function Show-MessageBoxWithTimeout {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [Parameter(Mandatory)]
        [string]$Title,
        [int]$TimeoutSeconds = 10,
        [System.Windows.Forms.Form]$OwnerForm
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Width = 400
    $form.Height = 180  # 高さを少し上げてもよい
    $form.StartPosition = "CenterScreen"

    # ラベル
    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Message
    $label.AutoSize = $true
    $label.Left = 20
    $label.Top = 20
    $form.Controls.Add($label)

    # Yesボタン (位置を下げる)
    $yesButton = New-Object System.Windows.Forms.Button
    $yesButton.Text = "Yes"
    $yesButton.Left = 50
    $yesButton.Top = 100  # 変更: 70 => 100
    $yesButton.Add_Click({
        $form.Tag = [System.Windows.Forms.DialogResult]::Yes
        $form.Close()
    })
    $form.Controls.Add($yesButton)

    # Noボタン (位置を下げる)
    $noButton = New-Object System.Windows.Forms.Button
    $noButton.Text = "No"
    $noButton.Left = 150
    $noButton.Top = 100  # 変更: 70 => 100
    $noButton.Add_Click({
        $form.Tag = [System.Windows.Forms.DialogResult]::No
        $form.Close()
    })
    $form.Controls.Add($noButton)

    # タイマー(秒数経過で自動クローズ)
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 1000
    $count = 0
    $timer.Add_Tick({
        $count++
        if ($count -ge $TimeoutSeconds) {
            $form.Tag = [System.Windows.Forms.DialogResult]::None
            $form.Close()
        }
    })
    $timer.Start()

    if ($OwnerForm) {
        $null = $form.ShowDialog($OwnerForm)
    } else {
        $null = $form.ShowDialog()
    }
    $timer.Stop()
    return $form.Tag
}


#====================== (2) Confirm-Overwrite =============================
function Confirm-Overwrite {
    param(
        [Parameter(Mandatory)]
        [string]$TargetFilePath,
        [System.Windows.Forms.Form]$OwnerForm
    )

    if (-not (Test-Path $TargetFilePath)) {
        return $true
    }

    # ファイル名のみ取得
    $fileName = [System.IO.Path]::GetFileName($TargetFilePath)

    # ファイル名だけをメッセージに表示
    $msg = "以下のファイルが既に存在します:`n$fileName`n" +
           "`n上書きしますか？(Yes=上書き / No=スキップ)"

    $title = "上書き確認"
    $res = Show-MessageBoxWithTimeout -Message $msg -Title $title -TimeoutSeconds 10 -OwnerForm $OwnerForm

    if ($res -eq [System.Windows.Forms.DialogResult]::Yes) {
        Write-Host "上書きを承諾 => $TargetFilePath"
        return $true
    }
    else {
        Write-Host "スキップ => $TargetFilePath"
        return $false
    }
}

#====================== (3) Load-PrivateKeyXmlFromUserStore (例) ==========
function Load-PrivateKeyXmlFromUserStore {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyContainerName
    )
    $provType = 1  
    $provider = "Microsoft Strong Cryptographic Provider"
    $csp = New-Object System.Security.Cryptography.CspParameters($provType, $provider, $KeyContainerName)
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($csp)
    $xml = $rsa.ToXmlString($true)
    $rsa.Dispose()
    return $xml
}

#====================== (4) Get-ModulusFromXmlString ======================
function Get-ModulusFromXmlString {
    param([string]$XmlString)
    if (-not $XmlString) { return $null }
    $spl = $XmlString -split "<Modulus>|</Modulus>"
    if ($spl.Count -lt 2) { return $null }
    return $spl[1].Trim()
}

#====================== (5) EncryptFileMulti =============================
function EncryptFileMulti {
    param(
        [string[]]$PublicKeyPaths,
        [string]$InputFilePath,
        [System.Windows.Forms.Form]$OwnerForm
    )

    if ($PublicKeyPaths.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            $OwnerForm,
            "公開鍵を1つ以上指定してください。",
            "エラー",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }
    if (-not (Test-Path $InputFilePath)) {
        [System.Windows.Forms.MessageBox]::Show(
            $OwnerForm,
            "暗号化対象ファイルが見つかりません: `n$InputFilePath",
            "エラー",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    $baseFileName = [System.IO.Path]::GetFileName($InputFilePath)
    $folder = [System.IO.Path]::GetDirectoryName($InputFilePath)
    $outEncPath = Join-Path $folder ($baseFileName + ".enc")

    if (-not (Confirm-Overwrite $outEncPath -OwnerForm $OwnerForm)) {
        return
    }

    # AES
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateKey()
    $aes.GenerateIV()

    $rsaEntries = @()
    foreach ($pubFile in $PublicKeyPaths) {
        if (-not (Test-Path $pubFile)) {
            Write-Host "警告: 公開鍵が見つかりません => $pubFile"
            continue
        }
        $pubXml = Get-Content -Path $pubFile -Raw
        $rsaPub = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsaPub.FromXmlString($pubXml)

        $modulus = Get-ModulusFromXmlString $pubXml
        if (-not $modulus) {
            Write-Host "警告: Modulus取得失敗 => $pubFile"
            $rsaPub.Dispose()
            continue
        }

        # RSA.Encrypt (PKCS#1 v1.5)
        $encKey = $rsaPub.Encrypt($aes.Key, $false)
        $rsaPub.Dispose()

        $rsaEntries += [PSCustomObject]@{
            Modulus = $modulus
            EncKey  = $encKey
        }
    }

    if ($rsaEntries.Count -eq 0) {
        Write-Host "エラー: 有効な公開鍵が0件 => 暗号化中止"
        return
    }

    $fsOut = [System.IO.File]::Open($outEncPath, 'Create')
    $bw = New-Object System.IO.BinaryWriter($fsOut)
    try {
        $n = $rsaEntries.Count
        $bw.Write([BitConverter]::GetBytes($n), 0, 4)

        foreach ($entry in $rsaEntries) {
            $modBytes = [System.Text.Encoding]::UTF8.GetBytes($entry.Modulus)
            $bw.Write([BitConverter]::GetBytes($modBytes.Length), 0, 4)
            $bw.Write($modBytes, 0, $modBytes.Length)

            $encLen = $entry.EncKey.Length
            $bw.Write([BitConverter]::GetBytes($encLen), 0, 4)
            $bw.Write($entry.EncKey, 0, $encLen)
        }

        $bw.Write($aes.IV, 0, $aes.IV.Length)

        $enc = $aes.CreateEncryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsOut, $enc, [System.Security.Cryptography.CryptoStreamMode]::Write)

        $fileNameBytes = [System.Text.Encoding]::UTF8.GetBytes($baseFileName)
        $cryptoStream.Write([BitConverter]::GetBytes($fileNameBytes.Length), 0, 4)
        $cryptoStream.Write($fileNameBytes, 0, $fileNameBytes.Length)

        $fsIn = [System.IO.File]::OpenRead($InputFilePath)
        try {
            $bufSize = $global:rsabit
            $buf = New-Object byte[] $bufSize
            while ($true) {
                $read = $fsIn.Read($buf, 0, $bufSize)
                if ($read -le 0) { break }
                $cryptoStream.Write($buf, 0, $read)
            }
            $cryptoStream.FlushFinalBlock()
        }
        finally {
            $fsIn.Close()
        }
    }
    finally {
        $bw.Close()
        $fsOut.Close()
        $aes.Dispose()
    }

    Write-Host "暗号化完了: $outEncPath (公開鍵=$($rsaEntries.Count)件)"
}

#====================== (6) DecryptFileMultiAuto =========================
function DecryptFileMultiAuto {
    param(
        [string]$InputFilePath,
        [System.Windows.Forms.Form]$OwnerForm
    )

    if (-not (Test-Path $InputFilePath)) {
        [System.Windows.Forms.MessageBox]::Show(
            $OwnerForm,
            "復号対象ファイルが見つかりません。`n$InputFilePath",
            "エラー",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    $fsIn = [System.IO.File]::OpenRead($InputFilePath)
    $br   = New-Object System.IO.BinaryReader($fsIn)
    try {
        $nBuf = $br.ReadBytes(4)
        if ($nBuf.Count -lt 4) {
            Write-Host "エラー: 公開鍵エントリ数が読み取れません"
            return
        }
        $n = [BitConverter]::ToInt32($nBuf, 0)
        if ($n -le 0 -or $n -gt 100) {
            Write-Host "エラー: 公開鍵エントリ数($n)が不正"
            return
        }
        Write-Host "公開鍵エントリ数: $n"

        $entries = @()
        for($i=0; $i -lt $n; $i++){
            $modLenBuf = $br.ReadBytes(4)
            if ($modLenBuf.Count -lt 4) {
                Write-Host "Modulus長読込失敗"
                return
            }
            $modLen = [BitConverter]::ToInt32($modLenBuf, 0)
            if ($modLen -le 0 -or $modLen -gt 1024) {
                Write-Host "Modulus長($modLen)が不正"
                return
            }
            $modStrBytes = $br.ReadBytes($modLen)
            if ($modStrBytes.Count -ne $modLen) {
                Write-Host "Modulus文字列を最後まで読めません"
                return
            }
            $modStr = [System.Text.Encoding]::UTF8.GetString($modStrBytes)

            $encLenBuf = $br.ReadBytes(4)
            if ($encLenBuf.Count -lt 4) {
                Write-Host "RSA暗号鍵長読込失敗"
                return
            }
            $encLen = [BitConverter]::ToInt32($encLenBuf, 0)
            if ($encLen -le 0 -or $encLen -gt $global:rsabit) {
                Write-Host "エラー: RSA暗号鍵長($encLen)が不正"
                return
            }
            $encKeyBytes = $br.ReadBytes($encLen)
            if ($encKeyBytes.Count -ne $encLen) {
                Write-Host "エラー: RSA暗号鍵読込失敗"
                return
            }

            $entries += [PSCustomObject]@{
                Modulus = $modStr
                EncKey  = $encKeyBytes
            }
        }

        $iv = $br.ReadBytes(16)
        if ($iv.Count -ne 16) {
            Write-Host "エラー: IVが読み取れません"
            return
        }

        $pubFiles = Get-ChildItem -Path $global:keysFolder -Filter '*.pubkey' -File
        if ($pubFiles.Count -eq 0) {
            Write-Host "エラー: keysに公開鍵が1つもありません"
            return
        }

        $aesKey = $null
        $found  = $false

        foreach ($ent in $entries) {
            $modEnc = $ent.Modulus
            $encAes = $ent.EncKey

            foreach ($pubf in $pubFiles) {
                $pubXml = Get-Content $pubf.FullName -Raw
                $modPub = Get-ModulusFromXmlString $pubXml
                if ($modPub -eq $modEnc) {
                    $keyBaseName = [System.IO.Path]::GetFileNameWithoutExtension($pubf.Name)
                    Write-Host "→ Modulus一致: $($pubf.Name) => KeyContainer=$keyBaseName"

                    $privXml = Load-PrivateKeyXmlFromUserStore -KeyContainerName $keyBaseName
                    if (-not $privXml) {
                        Write-Host "  秘密鍵を取得できません => スキップ"
                        continue
                    }

                    $rsaPriv = New-Object System.Security.Cryptography.RSACryptoServiceProvider
                    $rsaPriv.FromXmlString($privXml)
                    try {
                        $tmpAes = $rsaPriv.Decrypt($encAes, $false)
                        if ($tmpAes) {
                            Write-Host "  → 秘密鍵で復号成功!"
                            $aesKey = $tmpAes
                            $rsaPriv.Dispose()
                            $found = $true
                            break
                        }
                    }
                    catch {
                        Write-Host "  復号失敗 => $_"
                    }
                    $rsaPriv.Dispose()
                }
                if ($found) { break }
            }
            if ($found) { break }
        }

        if (-not $found -or -not $aesKey) {
            Write-Host "エラー: 一致する公開鍵 + 秘密鍵が見つかりませんでした"
            return
        }

        # AES復号
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $aesKey
        $aes.IV  = $iv

        $dec = $aes.CreateDecryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsIn, $dec, [System.Security.Cryptography.CryptoStreamMode]::Read)

        # ファイル名
        $fnameLenBuf = New-Object byte[] 4
        $count = $cryptoStream.Read($fnameLenBuf, 0, 4)
        if ($count -lt 4) {
            Write-Host "エラー: ファイル名長が読めません"
            return
        }
        $fnameLen = [BitConverter]::ToInt32($fnameLenBuf, 0)
        if ($fnameLen -le 0 -or $fnameLen -gt 512) {
            Write-Host "エラー: ファイル名長($fnameLen)が不正"
            return
        }
        $fnameBuf = New-Object byte[] $fnameLen
        $count = $cryptoStream.Read($fnameBuf, 0, $fnameLen)
        if ($count -lt $fnameLen) {
            Write-Host "エラー: ファイル名を最後まで読めません"
            return
        }
        $originalFileName = [System.Text.Encoding]::UTF8.GetString($fnameBuf)
        Write-Host "復号: 元ファイル名=$originalFileName"

        $outPath = Join-Path ([System.IO.Path]::GetDirectoryName($InputFilePath)) $originalFileName
        if (-not (Confirm-Overwrite $outPath -OwnerForm $OwnerForm)) {
            return
        }

        $fsOut = [System.IO.File]::Open($outPath, 'Create')
        try {
            $bufSize = $global:rsabit
            $buf = New-Object byte[] $bufSize
            while ($true) {
                $r2 = $cryptoStream.Read($buf, 0, $bufSize)
                if ($r2 -le 0) { break }
                $fsOut.Write($buf, 0, $r2)
            }
        }
        finally {
            $fsOut.Close()
        }

        Write-Host "復号完了: $outPath"

        $cryptoStream.Close()
        $cryptoStream.Dispose()
        $dec.Dispose()
        $aes.Dispose()
    }
    finally {
        $br.Close()
        $fsIn.Close()
    }
}

#====================== (7) Load-PubKeyList ==============================
function Load-PubKeyList {
    $pubFiles = Get-ChildItem -Path $global:keysFolder -Filter '*.pubkey' -File -ErrorAction SilentlyContinue
    $names = @()
    foreach ($pf in $pubFiles) {
        $names += [System.IO.Path]::GetFileNameWithoutExtension($pf.Name)
    }
    return $names | Sort-Object -Unique
}

#====================== (8) GUI構築 ======================================
$mainForm = New-Object System.Windows.Forms.Form
$mainForm.Text = "EasyCrypt.ps1 (Dialog in front)"
$mainForm.Size = New-Object System.Drawing.Size(620,520)
$mainForm.StartPosition = "CenterScreen"

$dropLabel = New-Object System.Windows.Forms.Label
$dropLabel.Text = "ここにファイルをドロップ"
$dropLabel.Size = New-Object System.Drawing.Size(580,150)
$dropLabel.Location = New-Object System.Drawing.Point(10,10)
$dropLabel.BorderStyle = "Fixed3D"
$dropLabel.TextAlign = "MiddleCenter"
$dropLabel.AllowDrop = $true
$mainForm.Controls.Add($dropLabel)

$fileListBox = New-Object System.Windows.Forms.ListBox
$fileListBox.Size = New-Object System.Drawing.Size(580,100)
$fileListBox.Location = New-Object System.Drawing.Point(10,170)
$mainForm.Controls.Add($fileListBox)

# ドラッグイベント
$dropLabel.Add_DragEnter({
    param($sender, $e)
    if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    } else {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::None
    }
})
$dropLabel.Add_DragDrop({
    param($sender, $e)
    $files = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
    foreach ($file in $files) {
        if (-not $fileListBox.Items.Contains($file)) {
            $null = $fileListBox.Items.Add($file)
        }
    }
    $dropLabel.Text = "ファイル数: $($fileListBox.Items.Count)"
})

$pubKeyLabel = New-Object System.Windows.Forms.Label
$pubKeyLabel.Text = "使用する公開鍵 (複数可):"
$pubKeyLabel.Location = New-Object System.Drawing.Point(10,280)
$pubKeyLabel.Size = New-Object System.Drawing.Size(180,20)
$mainForm.Controls.Add($pubKeyLabel)

$pubKeyCheckedList = New-Object System.Windows.Forms.CheckedListBox
$pubKeyCheckedList.Size = New-Object System.Drawing.Size(200,120)
$pubKeyCheckedList.Location = New-Object System.Drawing.Point(10,300)
$mainForm.Controls.Add($pubKeyCheckedList)

function RefreshKeyList {
    $pubKeyCheckedList.Items.Clear()
    $lst = Load-PubKeyList
    foreach ($k in $lst) {
        [void]$pubKeyCheckedList.Items.Add($k)
    }
}
RefreshKeyList

# 再読込
$reloadBtn = New-Object System.Windows.Forms.Button
$reloadBtn.Text = "再読込"
$reloadBtn.Location = New-Object System.Drawing.Point(230,300)
$reloadBtn.Size = New-Object System.Drawing.Size(80,30)
$reloadBtn.Add_Click({
    RefreshKeyList
})
$mainForm.Controls.Add($reloadBtn)

# 暗号化ボタン
$encBtn = New-Object System.Windows.Forms.Button
$encBtn.Text = "暗号化"
$encBtn.Location = New-Object System.Drawing.Point(10,430)
$encBtn.Size = New-Object System.Drawing.Size(100,30)
$encBtn.Add_Click({
    if ($fileListBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            $mainForm,
            "暗号化するファイルがありません。",
            "エラー",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    $selectedPubs = @()
    for($i=0; $i -lt $pubKeyCheckedList.Items.Count; $i++){
        if ($pubKeyCheckedList.GetItemChecked($i)) {
            $nameBase = $pubKeyCheckedList.Items[$i]
            $pubPath = Join-Path $global:keysFolder ($nameBase + ".pubkey")
            $selectedPubs += $pubPath
        }
    }
    if ($selectedPubs.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            $mainForm,
            "公開鍵を1つ以上チェックしてください。",
            "エラー",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    foreach ($f in $fileListBox.Items) {
        EncryptFileMulti -PublicKeyPaths $selectedPubs -InputFilePath $f -OwnerForm $mainForm
    }

    [System.Windows.Forms.MessageBox]::Show(
        $mainForm,
        "暗号化が完了しました。",
        "情報",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    $fileListBox.Items.Clear()
    $dropLabel.Text = "ここにファイルをドロップ"
})
$mainForm.Controls.Add($encBtn)

# 復号ボタン
$decBtn = New-Object System.Windows.Forms.Button
$decBtn.Text = "復号"
$decBtn.Location = New-Object System.Drawing.Point(120,430)
$decBtn.Size = New-Object System.Drawing.Size(100,30)
$decBtn.Add_Click({
    if ($fileListBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            $mainForm,
            "復号するファイルがありません。",
            "エラー",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return
    }

    foreach ($f in $fileListBox.Items) {
        DecryptFileMultiAuto -InputFilePath $f -OwnerForm $mainForm
    }

    [System.Windows.Forms.MessageBox]::Show(
        $mainForm,
        "復号処理が完了しました。",
        "情報",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    $fileListBox.Items.Clear()
    $dropLabel.Text = "ここにファイルをドロップ"
})
$mainForm.Controls.Add($decBtn)

# リストクリア
$clearBtn = New-Object System.Windows.Forms.Button
$clearBtn.Text = "クリア"
$clearBtn.Location = New-Object System.Drawing.Point(230,430)
$clearBtn.Size = New-Object System.Drawing.Size(80,30)
$clearBtn.Add_Click({
    $fileListBox.Items.Clear()
    $dropLabel.Text = "ここにファイルをドロップ"
})
$mainForm.Controls.Add($clearBtn)

# メインフォーム表示
$mainForm.Topmost = $true
$null = $mainForm.Add_Shown({ $mainForm.Activate() })
[void]$mainForm.ShowDialog()
