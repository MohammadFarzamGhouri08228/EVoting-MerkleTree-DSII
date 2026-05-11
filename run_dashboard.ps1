$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$mmrExe = Join-Path $root "mmr_sim.exe"
$webExe = Join-Path $root "evoteverify_web.exe"

$mmrSources = @(
    "src/main_sim.cpp",
    "src/mmr_simulation.cpp",
    "src/merkle_mountain_range.cpp",
    "src/sparse_merkle_tree.cpp",
    "src/sha256.cpp",
    "header/mmr_simulation.hpp",
    "header/sparse_merkle_tree.hpp",
    "sim/merkle_mmr_sim.html"
) | ForEach-Object { Join-Path $root $_ }
$buildMmr = -not (Test-Path $mmrExe)
if (-not $buildMmr) {
    $exeTime = (Get-Item $mmrExe).LastWriteTime
    $buildMmr = ($mmrSources | Where-Object { (Get-Item $_).LastWriteTime -gt $exeTime } | Select-Object -First 1) -ne $null
}

if ($buildMmr) {
    $existingBuild = Get-Process mmr_sim -ErrorAction SilentlyContinue
    if ($existingBuild) {
        Write-Host "[*] Stopping old MMR simulator before rebuild..."
        Stop-Process -Id $existingBuild.Id -Force
    }
}

if ($buildMmr) {
    Write-Host "[*] Building mmr_sim.exe..."
    g++ -std=c++17 -O2 -I. -Isim -o mmr_sim.exe src/main_sim.cpp src/mmr_simulation.cpp src/merkle_mountain_range.cpp src/sparse_merkle_tree.cpp src/sha256.cpp -lws2_32
}

$webSources = @(
    "src/main.cpp",
    "header/voting_system.hpp",
    "src/ballot.cpp",
    "src/voter_registry.cpp",
    "src/merkle_tree.cpp",
    "src/live_visualization_server.cpp",
    "src/sha256.cpp",
    "header/live_visualization_server.hpp"
) | ForEach-Object { Join-Path $root $_ }
$buildWeb = -not (Test-Path $webExe)
if (-not $buildWeb) {
    $webExeTime = (Get-Item $webExe).LastWriteTime
    $buildWeb = ($webSources | Where-Object { (Test-Path $_) -and (Get-Item $_).LastWriteTime -gt $webExeTime } | Select-Object -First 1) -ne $null
}

if ($buildWeb) {
    $existingWebBuild = Get-Process evoteverify_web -ErrorAction SilentlyContinue
    if ($existingWebBuild) {
        Write-Host "[*] Stopping old web homepage server before rebuild..."
        Stop-Process -Id $existingWebBuild.Id -Force
    }
    Write-Host "[*] Building evoteverify_web.exe..."
    g++ -std=c++17 -O2 -I. -o evoteverify_web.exe src/main.cpp src/ballot.cpp src/voter_registry.cpp src/merkle_tree.cpp src/live_visualization_server.cpp src/sha256.cpp -lws2_32
}

$existing = Get-Process mmr_sim -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Host "[*] Starting MMR simulator on http://127.0.0.1:9090/ ..."
    Start-Process -FilePath $mmrExe -WorkingDirectory $root -WindowStyle Hidden
    Start-Sleep -Milliseconds 1200
} else {
    Write-Host "[*] MMR simulator already running."
}

$existingWeb = Get-Process evoteverify_web -ErrorAction SilentlyContinue
if (-not $existingWeb) {
    Write-Host "[*] Starting visualization homepage on http://127.0.0.1:8080/ ..."
    Start-Process -FilePath $webExe -ArgumentList "--web-home" -WorkingDirectory $root -WindowStyle Hidden
    Start-Sleep -Milliseconds 1200
} else {
    Write-Host "[*] Visualization homepage already running."
}

Write-Host "[*] Opening visualization homepage ..."
Start-Process "http://127.0.0.1:8080/"
