############################################################################
# EasyCrypt.ps1 by Cala Maclir
############################################################################

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO

$rsabit = 4096

#=== 1) グローバル設定: keysフォルダ (カレント直下) =====================
$keysFolder = Join-Path (Get-Location) "keys"
if (-not (Test-Path $keysFolder)) {
    New-Item -ItemType Directory -Path $keysFolder | Out-Null
}

#-----------------------------------------------------------------------
# (A) ファイル上書き可否をユーザに確認する関数
#-----------------------------------------------------------------------
function Confirm-Overwrite {
    param(
        [Parameter(Mandatory)]
        [string]$TargetFilePath
    )

    if (-not (Test-Path $TargetFilePath)) {
        return $true
    }

    $msg   = "既にファイルが存在します。上書きしますか？`nYes = 上書き, No = スキップ"
    $title = "上書き確認"
    $btn   = [System.Windows.Forms.MessageBoxButtons]::YesNo
    $icon  = [System.Windows.Forms.MessageBoxIcon]::Question

    $res = [System.Windows.Forms.MessageBox]::Show($msg, $title, $btn, $icon)
    if ($res -eq [System.Windows.Forms.DialogResult]::Yes) {
        Write-Host "上書きを承諾 => $TargetFilePath"
        return $true
    }
    else {
        Write-Host "スキップ => $TargetFilePath"
        return $false
    }
}

#-----------------------------------------------------------------------
# (B) 公開鍵/秘密鍵XMLペアが正しく対応しているかを検証
#-----------------------------------------------------------------------
function Test-RSAKeyPair {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PrivateKeyXml,
        [Parameter(Mandatory=$true)]
        [string]$PublicKeyXml
    )

    try {
        # --- 秘密鍵を読み込むRSAオブジェクト ---
        $rsaPri = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsaPri.FromXmlString($PrivateKeyXml)

        # --- 公開鍵を読み込むRSAオブジェクト ---
        $rsaPub = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsaPub.FromXmlString($PublicKeyXml)

        # --- テスト用データ (署名→検証) ---
        $testData = [System.Text.Encoding]::UTF8.GetBytes("KeyPair検証用のサンプルデータ")

        # --- 秘密鍵で署名 ---
        $signature = $rsaPri.SignData(
            $testData,
            [System.Security.Cryptography.SHA256CryptoServiceProvider]::new()
        )

        # --- 公開鍵で検証 ---
        $isValid = $rsaPub.VerifyData(
            $testData,
            [System.Security.Cryptography.SHA256CryptoServiceProvider]::new(),
            $signature
        )
        return $isValid
    }
    catch {
        Write-Host "鍵ペアの検証中にエラーが発生しました: $($_.Exception.Message)"
        return $false
    }
}

#-----------------------------------------------------------------------
# (C) 鍵ペア生成
#    => 生成直後に Test-RSAKeyPair で検証
#-----------------------------------------------------------------------
function Generate-KeyPair {
    $id = (Get-Date).ToString("yyyyMMddHHmmss")

    # 4096bit の RSA鍵を作成
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($rsabit)
    $privateXml = $rsa.ToXmlString($true)
    $publicXml  = $rsa.ToXmlString($false)
    $rsa.Dispose()

    # まず検証
    $testOK = Test-RSAKeyPair -PrivateKeyXml $privateXml -PublicKeyXml $publicXml
    if (-not $testOK) {
        Write-Host "エラー: 作成した鍵ペアが正しく対応していません。（署名検証失敗）"
        return $null
    }

    # 検証OKならファイル保存
    $pvtPath = Join-Path $keysFolder "$id.pvtkey"
    $pubPath = Join-Path $keysFolder "$id.pubkey"

    $privateXml | Out-File -FilePath $pvtPath -Encoding UTF8 -Force
    $publicXml  | Out-File -FilePath $pubPath -Encoding UTF8 -Force

    Write-Host "鍵ペア生成＆検証OK: $pvtPath, $pubPath"
    return $id
}

#-----------------------------------------------------------------------
# (D) 公開鍵XMLから Modulus を抽出
#-----------------------------------------------------------------------
function Get-ModulusFromXmlString {
    param([string]$XmlString)
    if (-not $XmlString) { return $null }
    $spl = $XmlString -split "<Modulus>|</Modulus>"
    if ($spl.Count -lt 2) { return $null }
    return $spl[1].Trim()
}

#-----------------------------------------------------------------------
# (E) 複数公開鍵で暗号化 (ファイル先頭にエントリを並べる)
#-----------------------------------------------------------------------
function EncryptFileMulti {
    param(
        [Parameter(Mandatory)]
        [string[]]$PublicKeyPaths,

        [Parameter(Mandatory)]
        [string]$InputFilePath
    )

    if ($PublicKeyPaths.Count -eq 0) {
        Write-Host "エラー: 公開鍵が1つも指定されていません。"
        return
    }
    if (-not (Test-Path $InputFilePath)) {
        Write-Host "エラー: 暗号化対象ファイルが見つかりません。 -> $InputFilePath"
        return
    }

    # 出力ファイル => .enc
    $baseFileName = [System.IO.Path]::GetFileName($InputFilePath)
    $folder       = [System.IO.Path]::GetDirectoryName($InputFilePath)
    $outEncPath   = Join-Path $folder ($baseFileName + ".enc")

    # 上書き確認
    $ok = Confirm-Overwrite $outEncPath
    if (-not $ok) {
        return
    }

    # AES鍵 作成
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateKey()
    $aes.GenerateIV()

    # 公開鍵ごとに RSA暗号
    $rsaEntries = @()
    foreach ($pub in $PublicKeyPaths) {
        if (-not (Test-Path $pub)) {
            Write-Host "警告: 公開鍵が見つかりません => $pub"
            continue
        }
        $pubXml = Get-Content -Path $pub -Raw
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString($pubXml)

        $modulusBase64 = Get-ModulusFromXmlString $pubXml
        if (-not $modulusBase64) {
            Write-Host "警告: Modulus取得失敗 => $pub"
            $rsa.Dispose()
            continue
        }

        $encKey = $rsa.Encrypt($aes.Key, $false)
        $rsaEntries += [PSCustomObject]@{
            Modulus = $modulusBase64
            EncKey  = $encKey
        }
        $rsa.Dispose()
    }

    if ($rsaEntries.Count -eq 0) {
        Write-Host "エラー: 有効な公開鍵が0件 => 暗号化できません"
        return
    }

    # 出力ファイル書き込み
    $fsOut = [System.IO.File]::Open($outEncPath, 'Create')
    $bw = New-Object System.IO.BinaryWriter($fsOut)
    try {
        # 先頭: エントリ数 n
        $n = $rsaEntries.Count
        $bw.Write([BitConverter]::GetBytes($n), 0, 4)

        # 各エントリ
        foreach ($entry in $rsaEntries) {
            $modBytes = [System.Text.Encoding]::UTF8.GetBytes($entry.Modulus)
            $bw.Write([BitConverter]::GetBytes($modBytes.Length), 0, 4)
            $bw.Write($modBytes, 0, $modBytes.Length)

            $encLen = $entry.EncKey.Length
            $bw.Write([BitConverter]::GetBytes($encLen), 0, 4)
            $bw.Write($entry.EncKey, 0, $encLen)
        }

        # IV
        $bw.Write($aes.IV, 0, $aes.IV.Length)

        # AES暗号 (ファイル名 + 本体)
        $encryptor    = $aes.CreateEncryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsOut, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

        # ファイル名
        $fileNameBytes = [System.Text.Encoding]::UTF8.GetBytes($baseFileName)
        $lenBuf        = [BitConverter]::GetBytes($fileNameBytes.Length)
        $cryptoStream.Write($lenBuf, 0, 4)
        $cryptoStream.Write($fileNameBytes, 0, $fileNameBytes.Length)

        # 本体
        $fsIn = [System.IO.File]::OpenRead($InputFilePath)
        try {
            $bufSize = $rsabit
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

    Write-Host "暗号化完了: $outEncPath (公開鍵数=$($rsaEntries.Count))"
}

#-----------------------------------------------------------------------
# (F) 復号 (keys 内の全 .pvtkey を試す) + ファイル上書きチェック
#-----------------------------------------------------------------------
function DecryptFileMultiAuto {
    param(
        [Parameter(Mandatory)]
        [string]$InputFilePath
    )

    if (-not (Test-Path $InputFilePath)) {
        Write-Host "エラー: 復号対象ファイルが見つかりません => $InputFilePath"
        return
    }

    $pvtList = Get-ChildItem -Path $keysFolder -Filter '*.pvtkey' -File
    if ($pvtList.Count -eq 0) {
        Write-Host "エラー: 秘密鍵(.pvtkey)が1つもありません。"
        return
    }

    $fsIn = [System.IO.File]::OpenRead($InputFilePath)
    $br   = New-Object System.IO.BinaryReader($fsIn)

    try {
        $nBuf = $br.ReadBytes(4)
        if ($nBuf.Count -lt 4) {
            Write-Host "エラー: 公開鍵エントリ数を読めません。ファイル破損?"
            return
        }
        $n = [BitConverter]::ToInt32($nBuf, 0)
        if ($n -le 0 -or $n -gt 100) {
            Write-Host "エラー: 公開鍵エントリ数($n)が不正"
            return
        }
        Write-Host "公開鍵エントリ数: $n"

        $entries = @()
        for($i=0; $i -lt $n; $i++) {
            $modLenBuf = $br.ReadBytes(4)
            if ($modLenBuf.Count -lt 4) { Write-Host "Modulus長読込失敗"; return }
            $modLen = [BitConverter]::ToInt32($modLenBuf, 0)
            if ($modLen -le 0 -or $modLen -gt 1024) {
                Write-Host "Modulus長($modLen)が不正"
                return
            }
            $modStrBytes = $br.ReadBytes($modLen)
            if ($modStrBytes.Count -ne $modLen) {
                Write-Host "Modulus文字列読込失敗"
                return
            }
            $modStr = [System.Text.Encoding]::UTF8.GetString($modStrBytes)

            $encLenBuf = $br.ReadBytes(4)
            if ($encLenBuf.Count -lt 4) { Write-Host "RSA暗号鍵長読込失敗"; return }
            $encLen = [BitConverter]::ToInt32($encLenBuf, 0)
            if ($encLen -le 0 -or $encLen -gt $rsabit) {
                Write-Host "エラー: RSA暗号鍵長($encLen)が不正"
                return
            }
            $encKey = $br.ReadBytes($encLen)
            if ($encKey.Count -ne $encLen) {
                Write-Host "エラー: RSA暗号鍵読込失敗"
                return
            }

            $entries += [PSCustomObject]@{
                Modulus = $modStr
                EncKey  = $encKey
            }
        }

        # IV
        $iv = $br.ReadBytes(16)
        if ($iv.Count -ne 16) {
            Write-Host "エラー: IV読込失敗"
            return
        }

        #=== 全秘密鍵を試して AES鍵を復元 ===
        $aesKey = $null
        $success = $false

        foreach ($pvtItem in $pvtList) {
            $pvtXml = Get-Content -Path $pvtItem.FullName -Raw
            $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
            $rsa.FromXmlString($pvtXml)

            $modPvt = Get-ModulusFromXmlString $pvtXml
            if (-not $modPvt) {
                Write-Host "  警告: $($pvtItem.Name) からModulus取得できず -> スキップ"
                $rsa.Dispose()
                continue
            }
            Write-Host "→ 試行: $($pvtItem.Name) / Modulus=$modPvt"

            $hit = $false
            foreach ($ent in $entries) {
                if ($ent.Modulus -eq $modPvt) {
                    try {
                        $tmpKey = $rsa.Decrypt($ent.EncKey, $false)
                        if ($tmpKey) {
                            Write-Host "   成功: $($pvtItem.Name) でAES鍵復号!"
                            $aesKey = $tmpKey
                            $hit    = $true
                            break
                        }
                    }
                    catch {
                        Write-Host "   RSA復号失敗 => 不一致"
                    }
                }
            }
            $rsa.Dispose()
            if ($hit) {
                $success = $true
                break
            }
        }

        if (-not $success) {
            Write-Host "エラー: keys内のいずれの秘密鍵でも復号できませんでした"
            return
        }

        #=== AES復号ストリーム ===
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $aesKey
        $aes.IV  = $iv

        $decryptor = $aes.CreateDecryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsIn, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

        # ファイル名取得
        $fnameLenBuf = New-Object byte[] 4
        $count = $cryptoStream.Read($fnameLenBuf, 0, 4)
        if ($count -lt 4) {
            Write-Host "エラー: ファイル名長(4byte)が読めません"
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

        # 出力ファイルパス
        $folder = [System.IO.Path]::GetDirectoryName($InputFilePath)
        $outFilePath = Join-Path $folder $originalFileName

        # 上書き確認
        $ok = Confirm-Overwrite $outFilePath
        if (-not $ok) {
            return
        }

        # 書き込み
        $fsOut = [System.IO.File]::Open($outFilePath, 'Create')
        try {
            $bufSize = $rsabit
            $buf = New-Object byte[] $bufSize
            while ($true) {
                $rd = $cryptoStream.Read($buf, 0, $bufSize)
                if ($rd -le 0) { break }
                $fsOut.Write($buf, 0, $rd)
            }
        }
        finally {
            $fsOut.Close()
        }

        Write-Host "復号完了: $outFilePath"

        $cryptoStream.Close()
        $cryptoStream.Dispose()
        $decryptor.Dispose()
        $aes.Dispose()
    }
    finally {
        $br.Close()
        $fsIn.Close()
    }
}

#-----------------------------------------------------------------------
# (G) 公開鍵リスト (CheckedListBoxで複数選択)
#-----------------------------------------------------------------------
function Load-PubKeyList {
    $pubkeyFiles = Get-ChildItem -Path $keysFolder -Filter '*.pubkey' -File -ErrorAction SilentlyContinue
    $list = @()
    foreach ($f in $pubkeyFiles) {
        $list += $f.BaseName
    }
    return $list | Sort-Object -Unique
}

#-----------------------------------------------------------------------
# (H) GUI 構築
#-----------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "Multi-Key: Encrypt(Multi-Pub) & Decrypt(AutoAll-Pvt) w/ KeyPairCheck"
$form.Size = New-Object System.Drawing.Size(620,520)
$form.StartPosition = "CenterScreen"

$dropLabel = New-Object System.Windows.Forms.Label
$dropLabel.Text = "ここにファイルをドロップ"
$dropLabel.Size = New-Object System.Drawing.Size(580,150)
$dropLabel.Location = New-Object System.Drawing.Point(10,10)
$dropLabel.BorderStyle = "Fixed3D"
$dropLabel.TextAlign = "MiddleCenter"
$dropLabel.AllowDrop = $true
$form.Controls.Add($dropLabel)

$fileListBox = New-Object System.Windows.Forms.ListBox
$fileListBox.Size = New-Object System.Drawing.Size(580,100)
$fileListBox.Location = New-Object System.Drawing.Point(10,170)
$form.Controls.Add($fileListBox)

# ドラッグイベント
$dropLabel.Add_DragEnter({
    param($sender, $e)
    if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    }
    else {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::None
    }
})
$dropLabel.Add_DragDrop({
    param($sender, $e)
    $files = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
    foreach ($f in $files) {
        if (-not $fileListBox.Items.Contains($f)) {
            $null = $fileListBox.Items.Add($f)
        }
    }
    $dropLabel.Text = "ファイル数: $($fileListBox.Items.Count)"
})

# 公開鍵チェックリスト
$ckLabel = New-Object System.Windows.Forms.Label
$ckLabel.Text = "複数公開鍵をチェック:"
$ckLabel.Location = New-Object System.Drawing.Point(10,280)
$ckLabel.Size = New-Object System.Drawing.Size(180,20)
$form.Controls.Add($ckLabel)

$pubKeyCheckedList = New-Object System.Windows.Forms.CheckedListBox
$pubKeyCheckedList.Size = New-Object System.Drawing.Size(200,120)
$pubKeyCheckedList.Location = New-Object System.Drawing.Point(10,300)
$form.Controls.Add($pubKeyCheckedList)

function RefreshKeyList {
    $pubKeyCheckedList.Items.Clear()
    $lst = Load-PubKeyList
    foreach ($k in $lst) {
        $null = $pubKeyCheckedList.Items.Add($k)
    }
}
RefreshKeyList

# 鍵生成ボタン
$genBtn = New-Object System.Windows.Forms.Button
$genBtn.Text = "鍵生成"
$genBtn.Location = New-Object System.Drawing.Point(230,300)
$genBtn.Size = New-Object System.Drawing.Size(80,30)
$genBtn.Add_Click({
    $newId = Generate-KeyPair
    if ($newId) {
        [System.Windows.Forms.MessageBox]::Show("新しい鍵を生成＆検証しました: $newId")
        RefreshKeyList
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("鍵ペアの生成または検証に失敗しました。","エラー")
    }
})
$form.Controls.Add($genBtn)

# 再読込ボタン
$reloadBtn = New-Object System.Windows.Forms.Button
$reloadBtn.Text = "再読込"
$reloadBtn.Location = New-Object System.Drawing.Point(230,340)
$reloadBtn.Size = New-Object System.Drawing.Size(80,30)
$reloadBtn.Add_Click({
    RefreshKeyList
})
$form.Controls.Add($reloadBtn)

# Encrypt ボタン (複数公開鍵選択)
$encBtn = New-Object System.Windows.Forms.Button
$encBtn.Text = "暗号化"
$encBtn.Location = New-Object System.Drawing.Point(10,430)
$encBtn.Size = New-Object System.Drawing.Size(100,30)
$encBtn.Add_Click({
    if ($fileListBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("暗号化するファイルがありません。")
        return
    }

    # チェックされた公開鍵を収集
    $selectedPubs = @()
    for($i=0; $i -lt $pubKeyCheckedList.Items.Count; $i++){
        if ($pubKeyCheckedList.GetItemChecked($i)) {
            $keyName = $pubKeyCheckedList.Items[$i]
            $pubPath = Join-Path $keysFolder ($keyName + ".pubkey")
            $selectedPubs += $pubPath
        }
    }
    if ($selectedPubs.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("公開鍵を1つ以上チェックしてください。")
        return
    }

    foreach ($f in $fileListBox.Items) {
        EncryptFileMulti -PublicKeyPaths $selectedPubs -InputFilePath $f
    }
    [System.Windows.Forms.MessageBox]::Show("暗号化が完了しました。")
    $fileListBox.Items.Clear()
    $dropLabel.Text = "ここにファイルをドロップ"
})
$form.Controls.Add($encBtn)

# Decrypt ボタン (keys内の全pvtkeyを自動試行)
$decBtn = New-Object System.Windows.Forms.Button
$decBtn.Text = "Decrypt"
$decBtn.Location = New-Object System.Drawing.Point(120,430)
$decBtn.Size = New-Object System.Drawing.Size(100,30)
$decBtn.Add_Click({
    if ($fileListBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("復号するファイルがありません。")
        return
    }

    foreach ($f in $fileListBox.Items) {
        DecryptFileMultiAuto -InputFilePath $f
    }
    [System.Windows.Forms.MessageBox]::Show("復号試行が完了しました。(成功/失敗はコンソール参照)")
    $fileListBox.Items.Clear()
    $dropLabel.Text = "ここにファイルをドロップ"
})
$form.Controls.Add($decBtn)

# リストクリア
$clearBtn = New-Object System.Windows.Forms.Button
$clearBtn.Text = "クリア"
$clearBtn.Location = New-Object System.Drawing.Point(230,430)
$clearBtn.Size = New-Object System.Drawing.Size(80,30)
$clearBtn.Add_Click({
    $fileListBox.Items.Clear()
    $dropLabel.Text = "ここにファイルをドロップ"
})
$form.Controls.Add($clearBtn)

$form.Topmost = $true
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
