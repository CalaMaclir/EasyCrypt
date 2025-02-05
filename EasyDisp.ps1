################################################################################
# ╔════════════════════════════════════════════════════════════════════════╗
# ║                                                                        ║
# ║       EasyCrypt 暗号化ファイル構造表示ツール                             ║
# ║      （ファイルをドラッグ＆ドロップして内部構造を自動解析）              ║
# ║                                                                        ║
# ╚════════════════════════════════════════════════════════════════════════╝
################################################################################

#-------------------------
# 必要なアセンブリのロード
#-------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#-------------------------
# ヘルパー関数：4バイト整数の読み込み
#-------------------------
function Read-Int32 {
    param(
        [Parameter(Mandatory=$true)]
        [System.IO.BinaryReader]$Reader
    )
    $bytes = $Reader.ReadBytes(4)
    if ($bytes.Length -lt 4) {
        throw "整数読み込み失敗"
    }
    return [BitConverter]::ToInt32($bytes, 0)
}

#-------------------------
# 関数: Show-EncryptedFileStructure
#  指定した暗号化ファイルを読み込み、内部構造を解析して文字列で返す
#-------------------------
function Show-EncryptedFileStructure {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    if (-not (Test-Path $FilePath)) {
        return "ファイルが存在しません: $FilePath"
    }
    
    $result = ""
    
    try {
        $fs = [System.IO.File]::OpenRead($FilePath)
        $br = New-Object System.IO.BinaryReader($fs)

        $result += "■ 暗号化ファイル構造解析結果" + [Environment]::NewLine
        $result += "ファイルパス: $FilePath" + [Environment]::NewLine
        $result += "------------------------------------------------------------" + [Environment]::NewLine

        # 平文部：公開鍵ヘッダー部分
        $pubEntryCount = $br.ReadInt32()
        $result += "公開鍵エントリ数: $pubEntryCount" + [Environment]::NewLine

        for ($i = 0; $i -lt $pubEntryCount; $i++) {
            $result += "---- エントリ $($i+1) ----" + [Environment]::NewLine
            # モジュラス長 (4 bytes)
            $modLen = $br.ReadInt32()
            $result += "モジュラス長: $modLen bytes" + [Environment]::NewLine
            # モジュラス (UTF-8文字列)
            $modBytes = $br.ReadBytes($modLen)
            $modulus = [System.Text.Encoding]::UTF8.GetString($modBytes)
            $result += "モジュラス: $modulus" + [Environment]::NewLine

            # RSA暗号鍵長 (4 bytes)
            $rsaKeyLen = $br.ReadInt32()
            $result += "RSA暗号鍵長: $rsaKeyLen bytes" + [Environment]::NewLine
            # RSA暗号鍵 (バイナリデータ)
            $rsaEncKey = $br.ReadBytes($rsaKeyLen)
            $result += "RSA暗号鍵: (バイナリデータ, $($rsaEncKey.Length) bytes)" + [Environment]::NewLine
            $result += [Environment]::NewLine
        }

        # IV（初期化ベクトル：16 bytes, 平文）
        $iv = $br.ReadBytes(16)
        if ($iv.Length -ne 16) {
            $result += "IVの読み込み失敗" + [Environment]::NewLine
        }
        else {
            $result += "IV (初期化ベクトル): " + ([BitConverter]::ToString($iv)) + [Environment]::NewLine
        }

        # AES暗号化データ部分のサイズ計算
        $currentPosition = $fs.Position
        $totalLength = $fs.Length
        $aesDataLength = $totalLength - $currentPosition
        $result += "------------------------------------------------------------" + [Environment]::NewLine
        $result += "AES暗号化データ部分のサイズ: $aesDataLength bytes" + [Environment]::NewLine
        $result += "※この部分はAES暗号化されており、以下の構造を持ちます（復号前の状態）:" + [Environment]::NewLine
        $result += "    ├─ ファイル名長 (4 bytes, Int32)" + [Environment]::NewLine
        $result += "    ├─ ファイル名 (UTF-8文字列, 上記長)" + [Environment]::NewLine
        $result += "    └─ ファイル内容 (残りのバイナリデータ)" + [Environment]::NewLine

        $br.Close()
        $fs.Close()
    }
    catch {
        $result += "エラー: $_" + [Environment]::NewLine
    }
    
    return $result
}

#-------------------------
# GUI構築：フォームとドロップ領域、解析結果表示用テキストボックス
#-------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "EasyCrypt 暗号化ファイル構造表示"
$form.Size = New-Object System.Drawing.Size(700,500)
$form.StartPosition = "CenterScreen"
$form.AllowDrop = $true

# ドロップ領域のラベル
$dropLabel = New-Object System.Windows.Forms.Label
$dropLabel.Text = "ここに暗号化ファイルをドロップしてください"
$dropLabel.Size = New-Object System.Drawing.Size(660,60)
$dropLabel.Location = New-Object System.Drawing.Point(10,10)
$dropLabel.BorderStyle = "FixedSingle"
$dropLabel.TextAlign = "MiddleCenter"
$dropLabel.Font = New-Object System.Drawing.Font("Arial",12,[System.Drawing.FontStyle]::Bold)
$dropLabel.AllowDrop = $true
$form.Controls.Add($dropLabel)

# 解析結果を表示するテキストボックス
$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Multiline = $true
$textBox.ScrollBars = "Both"
$textBox.WordWrap = $false
$textBox.Font = New-Object System.Drawing.Font("Consolas",10)
$textBox.Size = New-Object System.Drawing.Size(660,380)
$textBox.Location = New-Object System.Drawing.Point(10,80)
$form.Controls.Add($textBox)

# ドラッグエンター時の処理
$dropLabel.Add_DragEnter({
    param($sender, $e)
    if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    }
    else {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::None
    }
})

# ドロップ時の処理：最初のファイルのみ処理して解析結果を表示
$dropLabel.Add_DragDrop({
    param($sender, $e)
    $files = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
    if ($files.Count -gt 0) {
        $selectedFile = $files[0]
        $dropLabel.Text = "選択されたファイル: " + [System.IO.Path]::GetFileName($selectedFile)
        $structureInfo = Show-EncryptedFileStructure -FilePath $selectedFile
        $textBox.Text = $structureInfo
    }
})

[void]$form.ShowDialog()
