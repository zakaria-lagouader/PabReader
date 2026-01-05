# Generate Certif

```powershell
$cert = New-SelfSignedCertificate `
  -DnsName "localhost","127.0.0.1" `
  -FriendlyName "PontBascule Local" `
  -CertStoreLocation "cert:\CurrentUser\My"

$pwd = ConvertTo-SecureString -String "1234" -Force -AsPlainText

Export-PfxCertificate -Cert $cert -FilePath ".\certificate.pfx" -Password $pwd
Export-Certificate  -Cert $cert -FilePath ".\certificate.cer"

Import-Certificate -FilePath ".\certificate.cer" -CertStoreLocation "cert:\LocalMachine\Root"
```

# Generate Final EXE

```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

Endpoint=https://son-pp.service.signalr.net;AccessKey=3N3A4u3fcTA582A8NvZoA1dIQysDrOOWRC3MzvnvAEhMuZbKYJ5LJQQJ99BFAC5T7U2XJ3w3AAAAASRSSrHa;Version=1.0;
