############################################################################
# EasyKeyManager.ps1
#   - ユーザーストア(秘密鍵) + keysフォルダ(公開鍵) を管理
#   - 秘密鍵Import時に公開鍵を生成・検証する
#   - 秘密鍵Export時は keys/secret フォルダに出力（既存ファイルがある場合、上書き確認）
#   - 鍵生成時に鍵名をバリデーション
#   - GUI
############################################################################

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO

#=== advapi32.dll を呼び出して ユーザーストア の鍵コンテナを列挙/削除 ===
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

#=== グローバル設定 ======================================================
$rsabit    = 4096
$provider  = "Microsoft Strong Cryptographic Provider"
$provType  = 1   # PROV_RSA_FULL (ユーザーストア)
$keysFolder = Join-Path (Get-Location) "keys"
if (-not (Test-Path $keysFolder)) {
    New-Item -ItemType Directory -Path $keysFolder | Out-Null
}

#-----------------------------------------------------------------------
# (A) ユーザーストアへの秘密鍵保存 / 取得
#-----------------------------------------------------------------------
function Save-PrivateKeyToUserStore {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyContainerName,
        [Parameter(Mandatory=$true)]
        [string]$PrivateKeyXml
    )
    $csp = New-Object System.Security.Cryptography.CspParameters($provType, $provider, $KeyContainerName)
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($csp)
    $rsa.PersistKeyInCsp = $true
    $rsa.FromXmlString($PrivateKeyXml)
    $rsa.Dispose()
}

function Load-PrivateKeyXmlFromUserStore {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyContainerName
    )
    $csp = New-Object System.Security.Cryptography.CspParameters($provType, $provider, $KeyContainerName)
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($csp)
    $xml = $rsa.ToXmlString($true)
    $rsa.Dispose()
    return $xml
}

function Remove-WindowsKey {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyContainerName
    )
    $hProv = New-Object IntPtr
    $ok = [KeyContainerRemover]::CryptAcquireContext(
        [ref] $hProv,
        $KeyContainerName,
        $provider,
        $provType,
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

#-----------------------------------------------------------------------
# (B) keysフォルダの .pubkey 一覧をロード
#-----------------------------------------------------------------------
function Load-PubKeyList {
    $pubFiles = Get-ChildItem -Path $keysFolder -Filter '*.pubkey' -File -ErrorAction SilentlyContinue
    $baseNames = $pubFiles | ForEach-Object { $_.BaseName }
    return $baseNames | Sort-Object -Unique
}

#-----------------------------------------------------------------------
# (C) RSA鍵ペアの署名検証テスト (import時の公開鍵ファイル作成前に使用)
#-----------------------------------------------------------------------
function Test-RSAKeyPair {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PrivateKeyXml
    )

    # RSAオブジェクト(秘密鍵付き)
    $rsaPri = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $rsaPri.FromXmlString($PrivateKeyXml)

    # 公開鍵XML
    $publicXml = $rsaPri.ToXmlString($false)

    # テストデータを署名→検証
    $testData = [System.Text.Encoding]::UTF8.GetBytes("KeyPairTestData")
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

#-----------------------------------------------------------------------
# (D) 鍵ペア生成 (ユーザーが鍵名を入力)
#     - GUIボタン内で呼び出し
#-----------------------------------------------------------------------
function Generate-KeyPair {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyName
    )

    # 1) 同名チェック
    $pubPath = Join-Path $keysFolder ($KeyName + ".pubkey")
    if (Test-Path $pubPath) {
        [System.Windows.Forms.MessageBox]::Show("同名の公開鍵ファイルが既に存在: $KeyName.pubkey","エラー")
        return $false
    }
    $containers = [KeyContainers]::GetUserKeyContainers($provType, $provider)
    if ($containers -contains $KeyName) {
        [System.Windows.Forms.MessageBox]::Show("同名のKeyContainerが既に存在: $KeyName","エラー")
        return $false
    }

    # 2) RSA鍵生成
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($rsabit)
    $privateXml = $rsa.ToXmlString($true)
    $publicXml  = $rsa.ToXmlString($false)
    $rsa.Dispose()

    # 3) 秘密鍵 => ユーザーストア
    Save-PrivateKeyToUserStore -KeyContainerName $KeyName -PrivateKeyXml $privateXml

    # 4) 公開鍵 => keysフォルダ
    $publicXml | Out-File -FilePath $pubPath -Encoding UTF8 -Force

    return $true
}

#-----------------------------------------------------------------------
# (E) 秘密鍵エクスポート / インポート
#    - Export先: keys/secret (既存ファイルがあればユーザーにYes/No確認)
#    - Import時: 
#       1) 既に同名のKeyContainerがあればエラー (中断)
#       2) 公開鍵をkeysに生成（事前に署名検証）
#-----------------------------------------------------------------------
function Export-PrivateKey {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyContainerName
    )

    $pvtXml = Load-PrivateKeyXmlFromUserStore -KeyContainerName $KeyContainerName

    # keys/secret フォルダを作る
    $secretFolder = Join-Path $keysFolder "secret"
    if (-not (Test-Path $secretFolder)) {
        New-Item -ItemType Directory -Path $secretFolder | Out-Null
    }

    $destPath = Join-Path $secretFolder ($KeyContainerName + ".pvtkey")
    if (Test-Path $destPath) {
        # --- ここで上書き確認ダイアログ ---
        $msg = "秘密鍵ファイルが既に存在します。上書きしますか？`n$destPath"
        $res = [System.Windows.Forms.MessageBox]::Show($msg, "上書き確認", [System.Windows.Forms.MessageBoxButtons]::YesNo)
        if ($res -ne [System.Windows.Forms.DialogResult]::Yes) {
            Write-Host "上書きキャンセル => $destPath"
            return
        }
    }

    $pvtXml | Out-File -FilePath $destPath -Encoding UTF8 -Force
    Write-Host "秘密鍵Export完了 => $destPath"
}

function Import-Keys {
    param(
        [Parameter(Mandatory=$true)]
        [string]$KeyFilePath
    )

    if (-not (Test-Path $KeyFilePath)) {
        Write-Host "ファイルがありません => $KeyFilePath"
        return
    }
    
    # ファイル拡張子をチェック (.pubkeyの場合は公開鍵ファイルとしてコピー)
    $ext = [System.IO.Path]::GetExtension($KeyFilePath).ToLower()
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($KeyFilePath)
    
    if ($ext -eq ".pubkey") {
        $destPath = Join-Path $keysFolder ([System.IO.Path]::GetFileName($KeyFilePath))
        if (Test-Path $destPath) {
            Write-Host "既に同名の公開鍵が存在 => $destPath (上書き回避)"
        }
        else {
            Copy-Item -Path $KeyFilePath -Destination $destPath
            Write-Host "公開鍵ファイルをコピーしました => $destPath"
        }
        return
    }

    # --- 以降は従来の秘密鍵(.pvtkey)インポート処理 ---
    $pvtXml = Get-Content -Path $KeyFilePath -Raw

    # 既に同名のKeyContainerがあるか確認
    $containers = [KeyContainers]::GetUserKeyContainers($provType, $provider)
    if ($containers -contains $baseName) {
        [System.Windows.Forms.MessageBox]::Show("KeyContainer '$baseName' が既に存在します。Import中止","エラー")
        return
    }

    # ユーザーストアに保存
    Save-PrivateKeyToUserStore -KeyContainerName $baseName -PrivateKeyXml $pvtXml
    Write-Host "秘密鍵Import完了 => KeyContainer: $baseName"

    # 公開鍵を生成＆署名検証
    $publicXml = Test-RSAKeyPair -PrivateKeyXml $pvtXml
    if (-not $publicXml) {
        [System.Windows.Forms.MessageBox]::Show("秘密鍵が不正のため公開鍵を作成できません","エラー")
        return
    }
    # 公開鍵を keys フォルダに保存 (同名 .pubkey)
    $pubPath = Join-Path $keysFolder ($baseName + ".pubkey")
    if (Test-Path $pubPath) {
        Write-Host "既に同名の公開鍵が存在 => $pubPath (上書き回避)"
        return
    }
    $publicXml | Out-File -FilePath $pubPath -Encoding UTF8
    Write-Host "→ 公開鍵作成 => $pubPath (署名検証OK)"
}


#=======================================================================
#                           GUI部
#=======================================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "EasyKeyManager"
$form.Size = New-Object System.Drawing.Size(640,450)
$form.StartPosition = "CenterScreen"
$form.Topmost = $true

$lbl = New-Object System.Windows.Forms.Label
$lbl.Text = "keys フォルダの .pubkey 一覧"
$lbl.Location = New-Object System.Drawing.Point(10,10)
$lbl.Size = New-Object System.Drawing.Size(300,20)
$form.Controls.Add($lbl)

$listBox = New-Object System.Windows.Forms.ListBox
$listBox.Location = New-Object System.Drawing.Point(10,40)
$listBox.Size     = New-Object System.Drawing.Size(300,300)
$form.Controls.Add($listBox)

function Refresh-PubList {
    $listBox.Items.Clear()
    $arr = Load-PubKeyList
    if ($arr.Count -eq 0) {
        $null = $listBox.Items.Add("(なし)")
    }
    else {
        $arr | ForEach-Object { $null = $listBox.Items.Add($_) }
    }
}
Refresh-PubList

#--- (補助) 鍵名バリデーション
function Validate-KeyName($name) {
    # 空や null は不可
    if (-not $name) { 
        return $false 
    }
    # パターン: 先頭から末尾まで、英数字 + _ - @ . を含む文字のみ許可
    # - と . は正規表現上、文字クラス内で特別扱いされる場合があるため、順番やエスケープに注意
    # ここではシンプルに [A-Za-z0-9_\-@\.]+ とする
    if ($name -match '^[A-Za-z0-9_\-@\.]+$') {
        return $true
    }
    else {
        return $false
    }
}

#=== 鍵生成ボタン ===
$btnGen = New-Object System.Windows.Forms.Button
$btnGen.Text = "鍵生成"
$btnGen.Location = New-Object System.Drawing.Point(330,40)
$btnGen.Size = New-Object System.Drawing.Size(120,30)
$btnGen.Add_Click({

    # --- 鍵名入力フォームを表示 ---
    $dlgForm = New-Object System.Windows.Forms.Form
    $dlgForm.Text = "鍵生成"
    $dlgForm.Width = 300
    $dlgForm.Height = 150
    $dlgForm.StartPosition = "CenterParent"
    $dlgForm.Topmost = $true

    $lbl2 = New-Object System.Windows.Forms.Label
    $lbl2.Text = "鍵名(半角英数, アンダースコア, ハイフン, @, .のみ)"
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

    $dlgForm.StartPosition = "CenterParent"
    $result = $dlgForm.ShowDialog($form)
    $keyName = $tb.Text.Trim()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        # --- 鍵名バリデーション ---
        if (-not (Validate-KeyName $keyName)) {
            [System.Windows.Forms.MessageBox]::Show("鍵名に使用できない文字が含まれています。`n(半角英数, アンダースコア, ハイフン, @, .のみ)","エラー")
            return
        }

        $ok = Generate-KeyPair -KeyName $keyName
        if ($ok) {
            [System.Windows.Forms.MessageBox]::Show("鍵ペア生成完了: $keyName","情報")
            Refresh-PubList
        }
    }
})
$form.Controls.Add($btnGen)

#--- 秘密鍵Exportボタン (UserStore -> keys/secret) ---
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

#--- 秘密鍵Importボタン (.pvtkey / .pubkey -> UserStore または keys フォルダにコピー) ---
$btnImp = New-Object System.Windows.Forms.Button
$btnImp.Text = "鍵Import"
$btnImp.Location = New-Object System.Drawing.Point(330,120)
$btnImp.Size = New-Object System.Drawing.Size(120,30)
$btnImp.Add_Click({
    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.InitialDirectory = $keysFolder
    # フィルタを "Key files (*.pvtkey;*.pubkey)" と "All files" に変更
    $ofd.Filter = "Key files (*.pvtkey;*.pubkey)|*.pvtkey;*.pubkey|All files (*.*)|*.*"
    $ofd.Multiselect = $false
    $result = $ofd.ShowDialog($form)
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        Import-Keys -KeyFilePath $ofd.FileName
        [System.Windows.Forms.MessageBox]::Show("鍵Import完了 (コンソール参照)","情報")
        Refresh-PubList
    }
})
$form.Controls.Add($btnImp)


#--- 再読込ボタン ---
$btnReload = New-Object System.Windows.Forms.Button
$btnReload.Text = "再読込"
$btnReload.Location = New-Object System.Drawing.Point(330,160)
$btnReload.Size = New-Object System.Drawing.Size(120,30)
$btnReload.Add_Click({
    Refresh-PubList
})
$form.Controls.Add($btnReload)

#--- 終了ボタン ---
$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = "閉じる"
$btnClose.Location = New-Object System.Drawing.Point(330,280)
$btnClose.Size = New-Object System.Drawing.Size(120,30)
$btnClose.Add_Click({
    $form.Close()
})
$form.Controls.Add($btnClose)

$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
