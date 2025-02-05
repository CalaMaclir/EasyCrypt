# ╔════════════════════════════════════════════════════════════════════════╗
# ║                                                                        ║
# ║                   EasyKeyManager by Cala Maclir                        ║
# ║                                                                        ║
# ╚════════════════════════════════════════════════════════════════════════╝

#===================================================
# ■ 必要アセンブリのロード
#===================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#===================================================
# ■ advapi32.dll を呼び出して ユーザーストア の鍵コンテナを列挙/削除
#===================================================
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public class KeyContainers {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CryptGetProvParam(
        IntPtr hProv,
        uint dwParam,
        byte[] pbData,
        ref uint dwDataLen,
        uint dwFlags);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CryptAcquireContext(
        ref IntPtr hProv,
        string pszContainer,
        string pszProvider,
        uint dwProvType,
        uint dwFlags);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CryptReleaseContext(
        IntPtr hProv,
        uint dwFlags);

    public static List<string> GetUserKeyContainers(uint provType, string provider) {
        List<string> containers = new List<string>();
        IntPtr hProv = IntPtr.Zero;

        // dwFlags=0 => ユーザーストア(ユーザーキーコンテナ)
        if(!CryptAcquireContext(ref hProv, null, provider, provType, 0)) {
            return containers;
        }
        try {
            uint dataLen = 0;
            // PP_ENUMCONTAINERS=0x6
            if(!CryptGetProvParam(hProv, 0x6, null, ref dataLen, 0x2)) {
                return containers;
            }
            byte[] data = new byte[dataLen];
            while(CryptGetProvParam(hProv, 0x6, data, ref dataLen, 0x2)) {
                string name = System.Text.Encoding.ASCII.GetString(data).TrimEnd('\0');
                containers.Add(name);
                dataLen = (uint)data.Length;
            }
        }
        finally {
            CryptReleaseContext(hProv, 0);
        }
        return containers;
    }

    public const uint CRYPT_DELETEKEYSET = 0x10;
}
"@

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class KeyContainerRemover {
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CryptAcquireContext(
        ref IntPtr hProv,
        string pszContainer,
        string pszProvider,
        uint dwProvType,
        uint dwFlags);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CryptReleaseContext(
        IntPtr hProv,
        uint dwFlags);
}
"@

# --- 先に共通関数を定義 ---
function Ensure-Directory {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

#===================================================
# ■ グローバル設定
#===================================================
$RsaBit      = 4096
$Provider    = "Microsoft Strong Cryptographic Provider"
$ProvType    = 1      # PROV_RSA_FULL (ユーザーストア)
$KeysFolder  = Join-Path (Get-Location) "keys"
Ensure-Directory $KeysFolder

#===================================================
# ■ 共通/汎用の補助関数
#===================================================
function Confirm-OverwriteFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    $msg = "ファイルが既に存在します。上書きしますか？`n$FilePath"
    $res = [System.Windows.Forms.MessageBox]::Show($msg, "上書き確認", [System.Windows.Forms.MessageBoxButtons]::YesNo)
    return ($res -eq [System.Windows.Forms.DialogResult]::Yes)
}

# キー名のバリデーション(半角英数, _, -, @, . のみ)
function Validate-KeyName {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    if (-not $Name) { return $false }
    if ($Name -match '^[A-Za-z0-9_\-@\.]+$') {
        return $true
    }
    return $false
}

#===================================================
# ■ (A) ユーザーストアへの秘密鍵保存 / 取得 / 削除
#===================================================
function Set-PrivateKeyToUserStore {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyContainerName,
        [Parameter(Mandatory=$true)]
        [string]$PrivateKeyXml
    )
    $csp = New-Object System.Security.Cryptography.CspParameters($ProvType, $Provider, $KeyContainerName)
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($csp)
    $rsa.PersistKeyInCsp = $true
    $rsa.FromXmlString($PrivateKeyXml)
    $rsa.Dispose()
}

function Get-PrivateKeyXmlFromUserStore {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyContainerName
    )
    $csp = New-Object System.Security.Cryptography.CspParameters($ProvType, $Provider, $KeyContainerName)
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($csp)
    $xml = $rsa.ToXmlString($true)
    $rsa.Dispose()
    return $xml
}

function Remove-PrivateKeyFromUserStore {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyContainerName
    )
    $hProv = New-Object IntPtr
    $ok = [KeyContainerRemover]::CryptAcquireContext(
        [ref]$hProv,
        $KeyContainerName,
        $Provider,
        $ProvType,
        [KeyContainers]::CRYPT_DELETEKEYSET
    )
    if ($ok) {
        [KeyContainerRemover]::CryptReleaseContext($hProv, 0) | Out-Null
        Write-Host "KeyContainer '$KeyContainerName' を削除しました。"
    }
    else {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host "KeyContainer '$KeyContainerName' の削除に失敗 (Win32Err=$err)"
    }
}

#===================================================
# ■ (B) keysフォルダの .pubkey 一覧
#===================================================
function Get-PubKeyList {
    $pubFiles = Get-ChildItem -Path $KeysFolder -Filter '*.pubkey' -File -ErrorAction SilentlyContinue
    $baseNames = $pubFiles | ForEach-Object { $_.BaseName }
    return $baseNames | Sort-Object -Unique
}

#===================================================
# ■ (C) RSA鍵ペアの署名検証 (Import時の公開鍵生成前にテスト)
#===================================================
function Test-RSAKeyPair {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PrivateKeyXml
    )

    # 秘密鍵つきRSA
    $rsaPri = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsaPri.FromXmlString($PrivateKeyXml)

    # 公開鍵XMLを取得
    $publicXml = $rsaPri.ToXmlString($false)

    # テストデータを署名→検証
    $testData  = [System.Text.Encoding]::UTF8.GetBytes("KeyPairTestData")
    $signature = $rsaPri.SignData($testData, [System.Security.Cryptography.SHA256CryptoServiceProvider]::new())
    $rsaPri.Dispose()

    $rsaPub = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsaPub.FromXmlString($publicXml)
    $ok = $rsaPub.VerifyData($testData, [System.Security.Cryptography.SHA256CryptoServiceProvider]::new(), $signature)
    $rsaPub.Dispose()

    if ($ok) {
        return $publicXml
    }
    else {
        return $null
    }
}

#===================================================
# ■ (D) 鍵ペア生成 (ユーザー入力名で作成)
#===================================================
function New-KeyPair {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyName
    )

    # 1) 同名チェック
    $pubPath = Join-Path $KeysFolder ($KeyName + ".pubkey")
    if (Test-Path $pubPath) {
        [System.Windows.Forms.MessageBox]::Show("同名の公開鍵ファイルが既に存在: $KeyName.pubkey","エラー")
        return $false
    }
    $containers = [KeyContainers]::GetUserKeyContainers($ProvType, $Provider)
    if ($containers -contains $KeyName) {
        [System.Windows.Forms.MessageBox]::Show("同名のKeyContainerが既に存在: $KeyName","エラー")
        return $false
    }

    # 2) RSA鍵生成
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($RsaBit)
    $privateXml = $rsa.ToXmlString($true)
    $publicXml  = $rsa.ToXmlString($false)
    $rsa.Dispose()

    # 3) 秘密鍵 => ユーザーストア保存
    Set-PrivateKeyToUserStore -KeyContainerName $KeyName -PrivateKeyXml $privateXml

    # 4) 公開鍵 => keysフォルダ
    $publicXml | Out-File -FilePath $pubPath -Encoding UTF8 -Force

    return $true
}

#===================================================
# ■ (E) 秘密鍵のExport / Import
#===================================================
function Export-PrivateKey {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyContainerName
    )
    $pvtXml = Get-PrivateKeyXmlFromUserStore -KeyContainerName $KeyContainerName

    # keys/secret フォルダを用意
    $secretFolder = Join-Path $KeysFolder "secret"
    Ensure-Directory $secretFolder

    $destPath = Join-Path $secretFolder ("$KeyContainerName.pvtkey")
    if (Test-Path $destPath) {
        if (-not (Confirm-OverwriteFile $destPath)) {
            Write-Host "上書きキャンセル => $destPath"
            return
        }
    }

    $pvtXml | Out-File -FilePath $destPath -Encoding UTF8 -Force
    Write-Host "秘密鍵Export完了 => $destPath"
}

function Import-KeyFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyFilePath
    )
    if (-not (Test-Path $KeyFilePath)) {
        Write-Host "ファイルがありません => $KeyFilePath"
        return
    }

    # 拡張子ごとに処理を分岐
    $ext      = [System.IO.Path]::GetExtension($KeyFilePath).ToLower()
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($KeyFilePath)

    if ($ext -eq ".pubkey") {
        # 公開鍵ファイルの場合 => keysフォルダにコピー
        $destPath = Join-Path $KeysFolder ([System.IO.Path]::GetFileName($KeyFilePath))
        if (Test-Path $destPath) {
            Write-Host "既に同名の公開鍵が存在 => $destPath (上書き回避)"
        }
        else {
            Copy-Item -Path $KeyFilePath -Destination $destPath
            Write-Host "公開鍵ファイルをコピーしました => $destPath"
        }
        return
    }

    # それ以外 => 秘密鍵(.pvtkey)としてImport
    $pvtXml = Get-Content -Path $KeyFilePath -Raw

    # 同名KeyContainerが既にあるかチェック
    $containers = [KeyContainers]::GetUserKeyContainers($ProvType, $Provider)
    if ($containers -contains $baseName) {
        [System.Windows.Forms.MessageBox]::Show("KeyContainer '$baseName' が既に存在します。Import中止","エラー")
        return
    }

    # ユーザーストアに保存
    Set-PrivateKeyToUserStore -KeyContainerName $baseName -PrivateKeyXml $pvtXml
    Write-Host "秘密鍵Import完了 => KeyContainer: $baseName"

    # 公開鍵を生成＆署名検証
    $publicXml = Test-RSAKeyPair -PrivateKeyXml $pvtXml
    if (-not $publicXml) {
        [System.Windows.Forms.MessageBox]::Show("秘密鍵が不正のため公開鍵を作成できません","エラー")
        return
    }

    # 公開鍵ファイルを keys フォルダに保存(同名 .pubkey)
    $pubPath = Join-Path $KeysFolder ("$baseName.pubkey")
    if (Test-Path $pubPath) {
        Write-Host "既に同名の公開鍵が存在 => $pubPath (上書き回避)"
        return
    }
    $publicXml | Out-File -FilePath $pubPath -Encoding UTF8
    Write-Host "→ 公開鍵作成 => $pubPath (署名検証OK)"
}

#===================================================
# ■ GUI 部
#===================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "EasyKeyManager"
$form.Size = New-Object System.Drawing.Size(500,450)
$form.StartPosition = "CenterScreen"
$form.Topmost = $true

# ラベル
$lbl = New-Object System.Windows.Forms.Label
$lbl.Text = "keys フォルダの .pubkey 一覧"
$lbl.Location = New-Object System.Drawing.Point(10,10)
$lbl.Size = New-Object System.Drawing.Size(300,20)
$form.Controls.Add($lbl)

# リストボックス
$listBox = New-Object System.Windows.Forms.ListBox
$listBox.Location = New-Object System.Drawing.Point(10,40)
$listBox.Size     = New-Object System.Drawing.Size(300,300)
$form.Controls.Add($listBox)

function Refresh-PubList {
    $listBox.Items.Clear()
    $arr = Get-PubKeyList
    if ($arr.Count -eq 0) {
        $null = $listBox.Items.Add("(なし)")
    }
    else {
        $arr | ForEach-Object { [void]$listBox.Items.Add($_) }
    }
}
Refresh-PubList

#-----------------------------------------------------------------------
# (補助) 鍵生成ボタン
#-----------------------------------------------------------------------
$btnGen = New-Object System.Windows.Forms.Button
$btnGen.Text = "鍵生成"
$btnGen.Location = New-Object System.Drawing.Point(330,40)
$btnGen.Size = New-Object System.Drawing.Size(120,30)
$btnGen.Add_Click({

    # 鍵名入力ダイアログ
    $dlgForm = New-Object System.Windows.Forms.Form
    $dlgForm.Text = "鍵生成"
    $dlgForm.Width = 300
    $dlgForm.Height = 150
    $dlgForm.StartPosition = "CenterParent"
    $dlgForm.Topmost = $true

    $lbl2 = New-Object System.Windows.Forms.Label
    $lbl2.Text = "鍵名(英数字, _, -, @, .)"
    $lbl2.AutoSize = $true
    $lbl2.Top = 10
    $lbl2.Left = 10
    $dlgForm.Controls.Add($lbl2)

    $tb = New-Object System.Windows.Forms.TextBox
    $tb.Top = 30
    $tb.Left = 10
    $tb.Width = 260
    $dlgForm.Controls.Add($tb)

    $okBtn = New-Object System.Windows.Forms.Button
    $okBtn.Text = "OK"
    $okBtn.Width = 80
    $okBtn.Height = 25
    $okBtn.Top = 70
    $okBtn.Left = 10
    $okBtn.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $dlgForm.Controls.Add($okBtn)

    $cancelBtn = New-Object System.Windows.Forms.Button
    $cancelBtn.Text = "Cancel"
    $cancelBtn.Width = 80
    $cancelBtn.Height = 25
    $cancelBtn.Top = 70
    $cancelBtn.Left = 100
    $cancelBtn.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $dlgForm.Controls.Add($cancelBtn)

    $dlgForm.AcceptButton = $okBtn
    $dlgForm.CancelButton = $cancelBtn

    $result = $dlgForm.ShowDialog($form)
    $keyName = $tb.Text.Trim()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        if (-not (Validate-KeyName $keyName)) {
            [System.Windows.Forms.MessageBox]::Show("鍵名に使用できない文字が含まれています。`n(英数字, _, -, @, .のみ)","エラー")
            return
        }
        $ok = New-KeyPair -KeyName $keyName
        if ($ok) {
            [System.Windows.Forms.MessageBox]::Show("鍵ペア生成完了: $keyName","情報")
            Refresh-PubList
        }
    }
})
$form.Controls.Add($btnGen)

#-----------------------------------------------------------------------
# 秘密鍵Exportボタン
#-----------------------------------------------------------------------
$btnExp = New-Object System.Windows.Forms.Button
$btnExp.Text = "秘密鍵Export"
$btnExp.Location = New-Object System.Drawing.Point(330,80)
$btnExp.Size = New-Object System.Drawing.Size(120,30)
$btnExp.Add_Click({
    $selected = $listBox.SelectedItem
    if (-not $selected -or $selected -eq "(なし)") {
        [System.Windows.Forms.MessageBox]::Show("Exportする鍵を選択してください","エラー")
        return
    }
    Export-PrivateKey -KeyContainerName $selected
    [System.Windows.Forms.MessageBox]::Show("秘密鍵Export完了 (コンソール参照)","情報")
})
$form.Controls.Add($btnExp)

#-----------------------------------------------------------------------
# 鍵Importボタン(.pvtkey / .pubkey -> ユーザーストア or keysにコピー)
#-----------------------------------------------------------------------
$btnImp = New-Object System.Windows.Forms.Button
$btnImp.Text = "鍵Import"
$btnImp.Location = New-Object System.Drawing.Point(330,120)
$btnImp.Size = New-Object System.Drawing.Size(120,30)
$btnImp.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.InitialDirectory = $KeysFolder
    $ofd.Filter = "Key files (*.pvtkey;*.pubkey)|*.pvtkey;*.pubkey|All files (*.*)|*.*"
    $ofd.Multiselect = $false
    $result = $ofd.ShowDialog($form)
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        Import-KeyFile -KeyFilePath $ofd.FileName
        [System.Windows.Forms.MessageBox]::Show("鍵Import完了 (コンソール参照)","情報")
        Refresh-PubList
    }
})
$form.Controls.Add($btnImp)

#-----------------------------------------------------------------------
# リスト再読込
#-----------------------------------------------------------------------
$btnReload = New-Object System.Windows.Forms.Button
$btnReload.Text = "再読込"
$btnReload.Location = New-Object System.Drawing.Point(330,160)
$btnReload.Size = New-Object System.Drawing.Size(120,30)
$btnReload.Add_Click({
    Refresh-PubList
})
$form.Controls.Add($btnReload)

#-----------------------------------------------------------------------
# 終了ボタン
#-----------------------------------------------------------------------
$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = "閉じる"
$btnClose.Location = New-Object System.Drawing.Point(330,280)
$btnClose.Size = New-Object System.Drawing.Size(120,30)
$btnClose.Add_Click({
    $form.Close()
})
$form.Controls.Add($btnClose)

# メインフォーム表示
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
