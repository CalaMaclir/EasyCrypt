############################################################################
# EasyCrypt.ps1 by Cala Maclir
############################################################################

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO

$rsabit = 4096

#=== 1) �O���[�o���ݒ�: keys�t�H���_ (�J�����g����) =====================
$keysFolder = Join-Path (Get-Location) "keys"
if (-not (Test-Path $keysFolder)) {
    New-Item -ItemType Directory -Path $keysFolder | Out-Null
}

#-----------------------------------------------------------------------
# (A) �t�@�C���㏑���ۂ����[�U�Ɋm�F����֐�
#-----------------------------------------------------------------------
function Confirm-Overwrite {
    param(
        [Parameter(Mandatory)]
        [string]$TargetFilePath
    )

    if (-not (Test-Path $TargetFilePath)) {
        return $true
    }

    $msg   = "���Ƀt�@�C�������݂��܂��B�㏑�����܂����H`nYes = �㏑��, No = �X�L�b�v"
    $title = "�㏑���m�F"
    $btn   = [System.Windows.Forms.MessageBoxButtons]::YesNo
    $icon  = [System.Windows.Forms.MessageBoxIcon]::Question

    $res = [System.Windows.Forms.MessageBox]::Show($msg, $title, $btn, $icon)
    if ($res -eq [System.Windows.Forms.DialogResult]::Yes) {
        Write-Host "�㏑�������� => $TargetFilePath"
        return $true
    }
    else {
        Write-Host "�X�L�b�v => $TargetFilePath"
        return $false
    }
}

#-----------------------------------------------------------------------
# (B) ���J��/�閧��XML�y�A���������Ή����Ă��邩������
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
        # --- �閧����ǂݍ���RSA�I�u�W�F�N�g ---
        $rsaPri = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsaPri.FromXmlString($PrivateKeyXml)

        # --- ���J����ǂݍ���RSA�I�u�W�F�N�g ---
        $rsaPub = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsaPub.FromXmlString($PublicKeyXml)

        # --- �e�X�g�p�f�[�^ (����������) ---
        $testData = [System.Text.Encoding]::UTF8.GetBytes("KeyPair���ؗp�̃T���v���f�[�^")

        # --- �閧���ŏ��� ---
        $signature = $rsaPri.SignData(
            $testData,
            [System.Security.Cryptography.SHA256CryptoServiceProvider]::new()
        )

        # --- ���J���Ō��� ---
        $isValid = $rsaPub.VerifyData(
            $testData,
            [System.Security.Cryptography.SHA256CryptoServiceProvider]::new(),
            $signature
        )
        return $isValid
    }
    catch {
        Write-Host "���y�A�̌��ؒ��ɃG���[���������܂���: $($_.Exception.Message)"
        return $false
    }
}

#-----------------------------------------------------------------------
# (C) ���y�A����
#    => ��������� Test-RSAKeyPair �Ō���
#-----------------------------------------------------------------------
function Generate-KeyPair {
    $id = (Get-Date).ToString("yyyyMMddHHmmss")

    # 4096bit �� RSA�����쐬
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($rsabit)
    $privateXml = $rsa.ToXmlString($true)
    $publicXml  = $rsa.ToXmlString($false)
    $rsa.Dispose()

    # �܂�����
    $testOK = Test-RSAKeyPair -PrivateKeyXml $privateXml -PublicKeyXml $publicXml
    if (-not $testOK) {
        Write-Host "�G���[: �쐬�������y�A���������Ή����Ă��܂���B�i�������؎��s�j"
        return $null
    }

    # ����OK�Ȃ�t�@�C���ۑ�
    $pvtPath = Join-Path $keysFolder "$id.pvtkey"
    $pubPath = Join-Path $keysFolder "$id.pubkey"

    $privateXml | Out-File -FilePath $pvtPath -Encoding UTF8 -Force
    $publicXml  | Out-File -FilePath $pubPath -Encoding UTF8 -Force

    Write-Host "���y�A����������OK: $pvtPath, $pubPath"
    return $id
}

#-----------------------------------------------------------------------
# (D) ���J��XML���� Modulus �𒊏o
#-----------------------------------------------------------------------
function Get-ModulusFromXmlString {
    param([string]$XmlString)
    if (-not $XmlString) { return $null }
    $spl = $XmlString -split "<Modulus>|</Modulus>"
    if ($spl.Count -lt 2) { return $null }
    return $spl[1].Trim()
}

#-----------------------------------------------------------------------
# (E) �������J���ňÍ��� (�t�@�C���擪�ɃG���g������ׂ�)
#-----------------------------------------------------------------------
function EncryptFileMulti {
    param(
        [Parameter(Mandatory)]
        [string[]]$PublicKeyPaths,

        [Parameter(Mandatory)]
        [string]$InputFilePath
    )

    if ($PublicKeyPaths.Count -eq 0) {
        Write-Host "�G���[: ���J����1���w�肳��Ă��܂���B"
        return
    }
    if (-not (Test-Path $InputFilePath)) {
        Write-Host "�G���[: �Í����Ώۃt�@�C����������܂���B -> $InputFilePath"
        return
    }

    # �o�̓t�@�C�� => .enc
    $baseFileName = [System.IO.Path]::GetFileName($InputFilePath)
    $folder       = [System.IO.Path]::GetDirectoryName($InputFilePath)
    $outEncPath   = Join-Path $folder ($baseFileName + ".enc")

    # �㏑���m�F
    $ok = Confirm-Overwrite $outEncPath
    if (-not $ok) {
        return
    }

    # AES�� �쐬
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateKey()
    $aes.GenerateIV()

    # ���J�����Ƃ� RSA�Í�
    $rsaEntries = @()
    foreach ($pub in $PublicKeyPaths) {
        if (-not (Test-Path $pub)) {
            Write-Host "�x��: ���J����������܂��� => $pub"
            continue
        }
        $pubXml = Get-Content -Path $pub -Raw
        $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        $rsa.FromXmlString($pubXml)

        $modulusBase64 = Get-ModulusFromXmlString $pubXml
        if (-not $modulusBase64) {
            Write-Host "�x��: Modulus�擾���s => $pub"
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
        Write-Host "�G���[: �L���Ȍ��J����0�� => �Í����ł��܂���"
        return
    }

    # �o�̓t�@�C����������
    $fsOut = [System.IO.File]::Open($outEncPath, 'Create')
    $bw = New-Object System.IO.BinaryWriter($fsOut)
    try {
        # �擪: �G���g���� n
        $n = $rsaEntries.Count
        $bw.Write([BitConverter]::GetBytes($n), 0, 4)

        # �e�G���g��
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

        # AES�Í� (�t�@�C���� + �{��)
        $encryptor    = $aes.CreateEncryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsOut, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

        # �t�@�C����
        $fileNameBytes = [System.Text.Encoding]::UTF8.GetBytes($baseFileName)
        $lenBuf        = [BitConverter]::GetBytes($fileNameBytes.Length)
        $cryptoStream.Write($lenBuf, 0, 4)
        $cryptoStream.Write($fileNameBytes, 0, $fileNameBytes.Length)

        # �{��
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

    Write-Host "�Í�������: $outEncPath (���J����=$($rsaEntries.Count))"
}

#-----------------------------------------------------------------------
# (F) ���� (keys ���̑S .pvtkey ������) + �t�@�C���㏑���`�F�b�N
#-----------------------------------------------------------------------
function DecryptFileMultiAuto {
    param(
        [Parameter(Mandatory)]
        [string]$InputFilePath
    )

    if (-not (Test-Path $InputFilePath)) {
        Write-Host "�G���[: �����Ώۃt�@�C����������܂��� => $InputFilePath"
        return
    }

    $pvtList = Get-ChildItem -Path $keysFolder -Filter '*.pvtkey' -File
    if ($pvtList.Count -eq 0) {
        Write-Host "�G���[: �閧��(.pvtkey)��1������܂���B"
        return
    }

    $fsIn = [System.IO.File]::OpenRead($InputFilePath)
    $br   = New-Object System.IO.BinaryReader($fsIn)

    try {
        $nBuf = $br.ReadBytes(4)
        if ($nBuf.Count -lt 4) {
            Write-Host "�G���[: ���J���G���g������ǂ߂܂���B�t�@�C���j��?"
            return
        }
        $n = [BitConverter]::ToInt32($nBuf, 0)
        if ($n -le 0 -or $n -gt 100) {
            Write-Host "�G���[: ���J���G���g����($n)���s��"
            return
        }
        Write-Host "���J���G���g����: $n"

        $entries = @()
        for($i=0; $i -lt $n; $i++) {
            $modLenBuf = $br.ReadBytes(4)
            if ($modLenBuf.Count -lt 4) { Write-Host "Modulus���Ǎ����s"; return }
            $modLen = [BitConverter]::ToInt32($modLenBuf, 0)
            if ($modLen -le 0 -or $modLen -gt 1024) {
                Write-Host "Modulus��($modLen)���s��"
                return
            }
            $modStrBytes = $br.ReadBytes($modLen)
            if ($modStrBytes.Count -ne $modLen) {
                Write-Host "Modulus������Ǎ����s"
                return
            }
            $modStr = [System.Text.Encoding]::UTF8.GetString($modStrBytes)

            $encLenBuf = $br.ReadBytes(4)
            if ($encLenBuf.Count -lt 4) { Write-Host "RSA�Í������Ǎ����s"; return }
            $encLen = [BitConverter]::ToInt32($encLenBuf, 0)
            if ($encLen -le 0 -or $encLen -gt $rsabit) {
                Write-Host "�G���[: RSA�Í�����($encLen)���s��"
                return
            }
            $encKey = $br.ReadBytes($encLen)
            if ($encKey.Count -ne $encLen) {
                Write-Host "�G���[: RSA�Í����Ǎ����s"
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
            Write-Host "�G���[: IV�Ǎ����s"
            return
        }

        #=== �S�閧���������� AES���𕜌� ===
        $aesKey = $null
        $success = $false

        foreach ($pvtItem in $pvtList) {
            $pvtXml = Get-Content -Path $pvtItem.FullName -Raw
            $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
            $rsa.FromXmlString($pvtXml)

            $modPvt = Get-ModulusFromXmlString $pvtXml
            if (-not $modPvt) {
                Write-Host "  �x��: $($pvtItem.Name) ����Modulus�擾�ł��� -> �X�L�b�v"
                $rsa.Dispose()
                continue
            }
            Write-Host "�� ���s: $($pvtItem.Name) / Modulus=$modPvt"

            $hit = $false
            foreach ($ent in $entries) {
                if ($ent.Modulus -eq $modPvt) {
                    try {
                        $tmpKey = $rsa.Decrypt($ent.EncKey, $false)
                        if ($tmpKey) {
                            Write-Host "   ����: $($pvtItem.Name) ��AES������!"
                            $aesKey = $tmpKey
                            $hit    = $true
                            break
                        }
                    }
                    catch {
                        Write-Host "   RSA�������s => �s��v"
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
            Write-Host "�G���[: keys���̂�����̔閧���ł������ł��܂���ł���"
            return
        }

        #=== AES�����X�g���[�� ===
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $aesKey
        $aes.IV  = $iv

        $decryptor = $aes.CreateDecryptor()
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($fsIn, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

        # �t�@�C�����擾
        $fnameLenBuf = New-Object byte[] 4
        $count = $cryptoStream.Read($fnameLenBuf, 0, 4)
        if ($count -lt 4) {
            Write-Host "�G���[: �t�@�C������(4byte)���ǂ߂܂���"
            return
        }
        $fnameLen = [BitConverter]::ToInt32($fnameLenBuf, 0)
        if ($fnameLen -le 0 -or $fnameLen -gt 512) {
            Write-Host "�G���[: �t�@�C������($fnameLen)���s��"
            return
        }

        $fnameBuf = New-Object byte[] $fnameLen
        $count = $cryptoStream.Read($fnameBuf, 0, $fnameLen)
        if ($count -lt $fnameLen) {
            Write-Host "�G���[: �t�@�C�������Ō�܂œǂ߂܂���"
            return
        }
        $originalFileName = [System.Text.Encoding]::UTF8.GetString($fnameBuf)

        Write-Host "����: ���t�@�C����=$originalFileName"

        # �o�̓t�@�C���p�X
        $folder = [System.IO.Path]::GetDirectoryName($InputFilePath)
        $outFilePath = Join-Path $folder $originalFileName

        # �㏑���m�F
        $ok = Confirm-Overwrite $outFilePath
        if (-not $ok) {
            return
        }

        # ��������
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

        Write-Host "��������: $outFilePath"

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
# (G) ���J�����X�g (CheckedListBox�ŕ����I��)
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
# (H) GUI �\�z
#-----------------------------------------------------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "Multi-Key: Encrypt(Multi-Pub) & Decrypt(AutoAll-Pvt) w/ KeyPairCheck"
$form.Size = New-Object System.Drawing.Size(620,520)
$form.StartPosition = "CenterScreen"

$dropLabel = New-Object System.Windows.Forms.Label
$dropLabel.Text = "�����Ƀt�@�C�����h���b�v"
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

# �h���b�O�C�x���g
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
    $dropLabel.Text = "�t�@�C����: $($fileListBox.Items.Count)"
})

# ���J���`�F�b�N���X�g
$ckLabel = New-Object System.Windows.Forms.Label
$ckLabel.Text = "�������J�����`�F�b�N:"
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

# �������{�^��
$genBtn = New-Object System.Windows.Forms.Button
$genBtn.Text = "������"
$genBtn.Location = New-Object System.Drawing.Point(230,300)
$genBtn.Size = New-Object System.Drawing.Size(80,30)
$genBtn.Add_Click({
    $newId = Generate-KeyPair
    if ($newId) {
        [System.Windows.Forms.MessageBox]::Show("�V�������𐶐������؂��܂���: $newId")
        RefreshKeyList
    }
    else {
        [System.Windows.Forms.MessageBox]::Show("���y�A�̐����܂��͌��؂Ɏ��s���܂����B","�G���[")
    }
})
$form.Controls.Add($genBtn)

# �ēǍ��{�^��
$reloadBtn = New-Object System.Windows.Forms.Button
$reloadBtn.Text = "�ēǍ�"
$reloadBtn.Location = New-Object System.Drawing.Point(230,340)
$reloadBtn.Size = New-Object System.Drawing.Size(80,30)
$reloadBtn.Add_Click({
    RefreshKeyList
})
$form.Controls.Add($reloadBtn)

# Encrypt �{�^�� (�������J���I��)
$encBtn = New-Object System.Windows.Forms.Button
$encBtn.Text = "�Í���"
$encBtn.Location = New-Object System.Drawing.Point(10,430)
$encBtn.Size = New-Object System.Drawing.Size(100,30)
$encBtn.Add_Click({
    if ($fileListBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("�Í�������t�@�C��������܂���B")
        return
    }

    # �`�F�b�N���ꂽ���J�������W
    $selectedPubs = @()
    for($i=0; $i -lt $pubKeyCheckedList.Items.Count; $i++){
        if ($pubKeyCheckedList.GetItemChecked($i)) {
            $keyName = $pubKeyCheckedList.Items[$i]
            $pubPath = Join-Path $keysFolder ($keyName + ".pubkey")
            $selectedPubs += $pubPath
        }
    }
    if ($selectedPubs.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("���J����1�ȏ�`�F�b�N���Ă��������B")
        return
    }

    foreach ($f in $fileListBox.Items) {
        EncryptFileMulti -PublicKeyPaths $selectedPubs -InputFilePath $f
    }
    [System.Windows.Forms.MessageBox]::Show("�Í������������܂����B")
    $fileListBox.Items.Clear()
    $dropLabel.Text = "�����Ƀt�@�C�����h���b�v"
})
$form.Controls.Add($encBtn)

# Decrypt �{�^�� (keys���̑Spvtkey���������s)
$decBtn = New-Object System.Windows.Forms.Button
$decBtn.Text = "Decrypt"
$decBtn.Location = New-Object System.Drawing.Point(120,430)
$decBtn.Size = New-Object System.Drawing.Size(100,30)
$decBtn.Add_Click({
    if ($fileListBox.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("��������t�@�C��������܂���B")
        return
    }

    foreach ($f in $fileListBox.Items) {
        DecryptFileMultiAuto -InputFilePath $f
    }
    [System.Windows.Forms.MessageBox]::Show("�������s���������܂����B(����/���s�̓R���\�[���Q��)")
    $fileListBox.Items.Clear()
    $dropLabel.Text = "�����Ƀt�@�C�����h���b�v"
})
$form.Controls.Add($decBtn)

# ���X�g�N���A
$clearBtn = New-Object System.Windows.Forms.Button
$clearBtn.Text = "�N���A"
$clearBtn.Location = New-Object System.Drawing.Point(230,430)
$clearBtn.Size = New-Object System.Drawing.Size(80,30)
$clearBtn.Add_Click({
    $fileListBox.Items.Clear()
    $dropLabel.Text = "�����Ƀt�@�C�����h���b�v"
})
$form.Controls.Add($clearBtn)

$form.Topmost = $true
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
