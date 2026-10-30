#requires -Version 7
param(
    [Parameter(Mandatory)][string]$WorkDirectory,
    [string]$Compiler = 'gcc'
)

$ErrorActionPreference = 'Stop'
$revision = '4f66b6ddf944cff07a2282dd5fa4c064d389966e'
$source = Join-Path ([IO.Path]::GetFullPath($WorkDirectory)) 'source'
$build = Join-Path ([IO.Path]::GetFullPath($WorkDirectory)) 'build'
$archive = Join-Path ([IO.Path]::GetFullPath($WorkDirectory)) 'source.tar.gz'
$samples = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\samples'))
$url = "https://chromium.googlesource.com/chromium/src/+archive/$revision/third_party/zlib.tar.gz"
foreach ($tool in @('cmake', 'ninja', 'tar', $Compiler)) {
    Get-Command $tool -ErrorAction Stop | Out-Null
}
New-Item -ItemType Directory -Path $source -Force | Out-Null
Invoke-WebRequest -Uri $url -OutFile $archive
tar -xzf $archive -C $source
if ($LASTEXITCODE -ne 0) { throw 'Source extraction failed' }
cmake -S $source -B $build -G Ninja "-DCMAKE_C_COMPILER=$Compiler" `
    -DCMAKE_BUILD_TYPE=Release -DZLIB_BUILD_TESTING=OFF -DZLIB_BUILD_SHARED=OFF `
    -DZLIB_INSTALL=OFF -DENABLE_SIMD_OPTIMIZATIONS=OFF -DUSE_ZLIB_RABIN_KARP_HASH=OFF
if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
cmake --build $build --target zlibstatic
if ($LASTEXITCODE -ne 0) { throw 'Native zlib build failed' }
$library = Get-ChildItem -LiteralPath $build -Filter '*zs.a'
if (@($library).Count -ne 1) { throw 'Expected one native static zlib archive' }
$executable = Join-Path $build 'generate_chromium_samples.exe'
& $Compiler -O2 -I $source -I $build (Join-Path $PSScriptRoot 'generate_chromium_samples.c') `
    $library.FullName -o $executable
if ($LASTEXITCODE -ne 0) { throw 'Fixture generator build failed' }
$inputFile = Join-Path $samples 'chromium_model_input.bin'
& $executable $inputFile (Join-Path $samples 'compressed_chromium_level')
if ($LASTEXITCODE -ne 0) { throw 'Fixture generation failed' }
$fixtures = foreach ($level in 0..9) {
    $file = Get-Item -LiteralPath (Join-Path $samples "compressed_chromium_level$level.deflate")
    [ordered]@{
        level = $level
        file = $file.Name
        bytes = $file.Length
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    }
}
[ordered]@{
    source_revision = $revision
    source_url = $url
    generator = 'tests/generate_chromium_samples.c'
    hash = 'Chromium non-CRC, 15-bit mask; SIMD and canonical-zlib hash disabled'
    window_bits = 15
    memory_level = 8
    strategy = 'Z_DEFAULT_STRATEGY'
    input_file = 'chromium_model_input.bin'
    input_sha256 = (Get-FileHash -LiteralPath $inputFile -Algorithm SHA256).Hash
    fixtures = @($fixtures)
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $samples 'chromium_samples.json') -Encoding utf8
