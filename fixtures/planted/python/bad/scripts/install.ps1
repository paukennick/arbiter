# Developer setup on Windows.
iex ((New-Object System.Net.WebClient).DownloadString('https://astral.sh/uv/install.ps1')) # expect: arbiter/supply.remote-script-piped
irm https://example.com/setup.ps1 | iex # expect: arbiter/supply.remote-script-piped
