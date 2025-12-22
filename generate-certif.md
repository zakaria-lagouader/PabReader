# Generate Certif

```powershell
$cert = New-SelfSignedCertificate `
  -DnsName "localhost","127.0.0.1" `
  -FriendlyName "PontBascule Local" `
  -CertStoreLocation "cert:\CurrentUser\My"

$pwd = ConvertTo-SecureString -String "1234" -Force -AsPlainText

Export-PfxCertificate -Cert $cert -FilePath ".\certificate.pfx" -Password $pwd
Export-Certificate  -Cert $cert -FilePath ".\certificate.cer"

Import-Certificate -FilePath ".\certificate.cer" -CertStoreLocation "cert:\CurrentUser\Root"
```

# Generate Final EXE

```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```
