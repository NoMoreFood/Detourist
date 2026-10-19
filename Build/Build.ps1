param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [ValidateRange(1, 32)][int]$BuildJobs = 1,
    [ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version = '1.0.0',
    [string]$StageDirectory = (Join-Path $PSScriptRoot 'PackageStage'),
    [switch]$Test,
    [switch]$Sign,
    [string]$CertificateThumbprint = $env:DETOURIST_SIGNING_CERTIFICATE_THUMBPRINT,
    [string]$TimestampUrl = $env:DETOURIST_TIMESTAMP_URL
)

$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskStage = [IO.Path]::GetFullPath($StageDirectory)
$taskExpectedStage = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'PackageStage'))
if ($taskStage -ne $taskExpectedStage) { throw 'The package stage must be the Build/PackageStage directory.' }

# Resolve the Visual Studio 2026 toolchain before configuring either architecture.
$taskVswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $taskVswhere)) { throw 'Visual Studio Installer is required.' }
$taskVs = & $taskVswhere -latest -version '[18.0,19.0)' -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -or -not $taskVs) { throw 'Visual Studio 2026 with C++ desktop tools is required.' }
$taskCmake = Join-Path $taskVs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$taskCtest = Join-Path (Split-Path -Parent $taskCmake) 'ctest.exe'
$taskWix = Get-Command wix.exe -ErrorAction SilentlyContinue
if (-not $taskWix) { throw 'WiX Toolset 7 is required to build the MSI.' }
if ((& $taskWix.Source --version) -notmatch '^7\.') { throw 'WiX Toolset 7 is required to build the MSI.' }
if (-not (Get-Command dotnet.exe -ErrorAction SilentlyContinue)) { throw '.NET 10 SDK is required.' }
if ($Sign -and (-not $CertificateThumbprint -or -not $TimestampUrl))
{
    throw 'Signing requires a certificate thumbprint and timestamp URL.'
}

$taskArchitectures = @(
    @{ Preset = 'windows-x64'; Build = (Join-Path $taskRoot 'Build\Temp\x64'); Destination = '' },
    @{ Preset = 'windows-x86'; Build = (Join-Path $taskRoot 'Build\Temp\x86'); Destination = 'x86' }
)
foreach ($taskArchitecture in $taskArchitectures)
{
    # Refresh CMake's compiler discovery if Visual Studio removed the cached toolset.
    $taskConfigure = @('--preset', $taskArchitecture.Preset, '-S', $taskRoot)
    $taskBuildPattern = [System.Management.Automation.WildcardPattern]::Escape($taskArchitecture.Build)
    $taskCachedCompiler = Get-ChildItem -File -Path "$taskBuildPattern\CMakeFiles\*\CMakeCXXCompiler.cmake" `
        -ErrorAction SilentlyContinue | Select-String -Pattern '^set\(CMAKE_CXX_COMPILER "([^"]+)"\)$'
    if ($taskCachedCompiler | Where-Object { -not (Test-Path -LiteralPath $_.Matches[0].Groups[1].Value) })
    {
        $taskConfigure += '--fresh'
    }
    & $taskCmake @taskConfigure
    if ($LASTEXITCODE) { throw "CMake configuration failed for $($taskArchitecture.Preset)." }
    & $taskCmake --build $taskArchitecture.Build --config $Configuration --parallel $BuildJobs -- `
        "/p:MultiProcMaxCount=$BuildJobs" "/p:CL_MPCount=$BuildJobs" /p:EnforceProcessCountAcrossBuilds=true
    if ($LASTEXITCODE) { throw "Build failed for $($taskArchitecture.Preset)." }
}

# Run the native suites before assembling the release payload when requested.
if ($Test)
{
    foreach ($taskArchitecture in $taskArchitectures)
    {
        & $taskCtest --test-dir $taskArchitecture.Build -C $Configuration --output-on-failure
        if ($LASTEXITCODE) { throw "Tests failed for $($taskArchitecture.Preset)." }
    }
}

# Publish the desktop app, then install native components into the matching runtime directories.
if (Test-Path -LiteralPath $taskStage) { Remove-Item -LiteralPath $taskStage -Recurse -Force }
New-Item -ItemType Directory -Path $taskStage | Out-Null
$taskDesktop = Join-Path $taskRoot 'Source\Detourist.Desktop\Detourist.Desktop.csproj'
& dotnet publish $taskDesktop --configuration $Configuration --runtime win-x64 --self-contained true `
    --output $taskStage "-p:Version=$Version"
if ($LASTEXITCODE) { throw 'Desktop publishing failed.' }
foreach ($taskArchitecture in $taskArchitectures)
{
    & $taskCmake --install $taskArchitecture.Build --config $Configuration `
        --prefix (Join-Path $taskStage $taskArchitecture.Destination)
    if ($LASTEXITCODE) { throw "Native staging failed for $($taskArchitecture.Preset)." }
}

if ($Sign)
{
    # Sign only project binaries; dependency binaries retain their publisher signatures.
    $taskSdkBin = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $taskSignTool = Get-ChildItem -LiteralPath $taskSdkBin -Directory | Sort-Object Name -Descending | ForEach-Object {
        Join-Path $_.FullName 'x64\signtool.exe'
    } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $taskSignTool) { throw 'Windows SDK SignTool is required for signing.' }
    function Set-ArtifactSignature([string]$Path)
    {
        & $taskSignTool sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $Path
        if ($LASTEXITCODE) { throw "Signing failed for $Path." }
    }
    $taskBinaries = Get-ChildItem -LiteralPath $taskStage -Recurse -File | Where-Object {
        $_.Name -match '^Detourist.*\.(exe|dll)$'
    }
    foreach ($taskBinary in $taskBinaries)
    {
        Set-ArtifactSignature $taskBinary.FullName
    }
}

# Produce both portable and Windows Installer distributions from the same staged files.
$taskArtifacts = Join-Path $taskRoot 'Build\Output'
New-Item -ItemType Directory -Force -Path $taskArtifacts | Out-Null
$taskBaseName = "Detourist-$Version-win-x64"
$taskZip = Join-Path $taskArtifacts "$taskBaseName.zip"
$taskMsi = Join-Path $taskArtifacts "$taskBaseName.msi"
Compress-Archive -Path (Join-Path $taskStage '*') -DestinationPath $taskZip -Force
& $taskWix.Source build (Join-Path $taskRoot 'Build\Installer\Detourist.wxs') -arch x64 `
    -d "ProductVersion=$Version" -b "Payload=$taskStage" -out $taskMsi -pdbtype none
if ($LASTEXITCODE) { throw 'MSI creation failed.' }
& $taskWix.Source msi validate $taskMsi
if ($LASTEXITCODE) { throw 'MSI validation failed.' }
if ($Sign) { Set-ArtifactSignature $taskMsi }
Write-Host "Built $taskZip"
Write-Host "Built $taskMsi"
