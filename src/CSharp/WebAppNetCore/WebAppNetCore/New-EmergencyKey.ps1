#Requires -Version 7.2
param(
    [Parameter(Mandatory)][string]$OutputDirectory,
    [Parameter(Mandatory)][string]$Audience,
    [string]$KeyId = 'oidc-emergency-encryption',
    [string]$ApplicationIdentity
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This PoC uses Windows DPAPI.' }
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory) -or $destination.StartsWith('\\') -or (Test-Path -LiteralPath $destination)) { throw 'Use a new absolute local directory outside the application and repositories.' }
for ($parent = [IO.DirectoryInfo]::new($destination); $null -ne $parent; $parent = $parent.Parent) {
    if (Test-Path -LiteralPath (Join-Path $parent.FullName '.git')) { throw 'Do not create private keys inside a source repository.' }
}
if ([string]::IsNullOrWhiteSpace($Audience) -or [string]::IsNullOrWhiteSpace($KeyId)) { throw 'Audience and key ID are required.' }
$scriptRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
if (($destination.TrimEnd('\') + '\').StartsWith($scriptRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Private keys must be outside the application directory.' }
New-Item -ItemType Directory -Path $destination | Out-Null
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
foreach ($identity in @($owner, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
if ($ApplicationIdentity) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($ApplicationIdentity, 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')) }
Set-Acl -LiteralPath $destination -AclObject $acl
function Encode-PublicBytes([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_') }
$key = [Security.Cryptography.RSA]::Create(2048)
try {
    $entropy = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes('OidcSample.Emergency.EncryptionKey.v1|' + $Audience))
    $protected = [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($key.ExportRSAPrivateKeyPem()), $entropy, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    [IO.File]::WriteAllBytes((Join-Path $destination 'decryption-key.bin'), $protected)
    $public = $key.ExportParameters($false)
    $jwk = [ordered]@{ kty='RSA'; kid=$KeyId; alg='RSA-OAEP'; use='enc'; n=(Encode-PublicBytes $public.Modulus); e=(Encode-PublicBytes $public.Exponent) }
    [IO.File]::WriteAllText((Join-Path $destination 'encryption-public.jwk.json'), ($jwk | ConvertTo-Json))
} finally { $key.Dispose() }
'Created a protected private key and public JWK. Keep this directory outside source control.'
