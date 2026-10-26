# Developer setup on Windows.
Invoke-WebRequest -Uri https://astral.sh/uv/0.4.30/install.ps1 -OutFile install.ps1
if ((Get-FileHash install.ps1 -Algorithm SHA256).Hash -ne '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef') { throw 'checksum mismatch' }
& ./install.ps1
