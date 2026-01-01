param(
    [string]$Source = ".\osint-original",
    [string]$Dest = ".\deploy",
    [switch]$CreateZip = $true,
    [switch]$Verbose = $false
)

$ErrorActionPreference = 'Stop'
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$copiedCount = 0
$skippedCount = 0

function Log {
    param([string]$Message, [string]$Level = "INFO")
    $time = Get-Date -Format "HH:mm:ss"
    $color = @{"INFO" = "Green"; "WARN" = "Yellow"; "ERROR" = "Red"}[$Level]
    Write-Host "[$time] [$Level] $Message" -ForegroundColor $color
}

function ValidatePath {
    param([string]$Path, [string]$Type = "path")
    if (-not (Test-Path $Path)) {
        Log "ERROR: $Type not found at '$Path'" "ERROR"
        return $false
    }
    return $true
}

# Initialize
Log "=== OSINT Labs Build & Deploy ===" "INFO"
Log "Start time: $timestamp" "INFO"

# Resolve paths
if (-not (ValidatePath $Source "Source")) { exit 1 }
$SourcePath = (Resolve-Path $Source).ProviderPath
$DestPath = (Resolve-Path -LiteralPath $Dest -ErrorAction SilentlyContinue) -replace "\\$", ''
if (-not $DestPath) { $DestPath = Join-Path (Get-Location) $Dest }

Log "Source: $SourcePath" "INFO"
Log "Destination: $DestPath" "INFO"

# Clean destination
if (Test-Path $DestPath) {
    Log "Clearing destination folder..." "INFO"
    Remove-Item -Path $DestPath -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $DestPath -Force | Out-Null
Log "Destination ready" "INFO"

# Define file groups
$htmlFiles = @('index.html','dashboard.html','login.html','maintenance.html','features.html','pricing.html','notes.html','team.html','contact.html','register.html','about.html','logins.html')
$imageFiles = @('image.png','image2.png')
$cssFiles = @('seeknow.css','dashboard.css')
$jsFiles = @('seeknow.js','dashboard-user.js','dashboard-admin.js','main.js')
$helperFiles = @('netlify.toml','NETLIFY_DEPLOYMENT.md','404.html','_redirects')

# Copy files by category
$fileLists = @(
    @{ "name" = "HTML Files"; "files" = $htmlFiles },
    @{ "name" = "Images"; "files" = $imageFiles },
    @{ "name" = "Root CSS"; "files" = $cssFiles },
    @{ "name" = "Root JS"; "files" = $jsFiles },
    @{ "name" = "Helpers"; "files" = $helperFiles }
)

foreach ($category in $fileLists) {
    $categoryName = $category.name
    $fileList = $category.files
    Log "Processing $categoryName..." "INFO"
    foreach ($file in $fileList) {
        $srcFile = Join-Path $SourcePath $file
        if (Test-Path $srcFile) {
            try {
                Copy-Item -Path $srcFile -Destination $DestPath -Force
                $copiedCount++
                Log "  [OK] Copied $file" "INFO"
            } catch {
                Log "  [FAIL] Failed to copy $file" "ERROR"
            }
        } else {
            $skippedCount++
            if ($Verbose) { Log "  [SKIP] $file (not found)" "WARN" }
        }
    }
}

# Copy directories
$directories = @('assets', 'data')
foreach ($dir in $directories) {
    $srcDir = Join-Path $SourcePath $dir
    if (Test-Path $srcDir) {
        Log "Copying directory: $dir/..." "INFO"
        try {
            Copy-Item -Path $srcDir -Destination $DestPath -Recurse -Force
            Log "  [OK] $dir copied successfully" "INFO"
        } catch {
            Log "  [FAIL] Failed to copy $dir" "ERROR"
        }
    } else {
        Log "  [SKIP] $dir not found" "WARN"
    }
}

# Verify critical files
Log "Verifying deployment..." "INFO"
$criticalFiles = @('index.html','team.html','seeknow.css','data/team.json','assets/js/seeknow.js')
$allValid = $true
foreach ($file in $criticalFiles) {
    $destFile = Join-Path $DestPath $file
    if (Test-Path $destFile) {
        Log "  [OK] $file verified" "INFO"
    } else {
        Log "  [MISSING] $file" "ERROR"
        $allValid = $false
    }
}

if (-not $allValid) {
    Log "Deployment verification FAILED" "ERROR"
    exit 1
}

# Create ZIP archive if requested
if ($CreateZip) {
    Log "Creating deployment archive..." "INFO"
    $parent = Split-Path -Path $DestPath -Parent
    $zipName = "deploy_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
    $zipPath = Join-Path $parent $zipName
    
    try {
        Compress-Archive -Path (Join-Path $DestPath '*') -DestinationPath $zipPath -Force
        $zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
        Log "  [OK] Archive created: $zipName ($zipSize MB)" "INFO"
    } catch {
        Log "  [FAIL] Archive creation failed" "ERROR"
    }
}

# Summary
Log "=== Build Summary ===" "INFO"
Log "Files copied: $copiedCount" "INFO"
Log "Files skipped: $skippedCount" "INFO"
Log "Deploy path: $DestPath" "INFO"
Log "Deployment completed successfully!" "INFO"
# Git operations
Log "=== Git Operations ===" "INFO"
try {
    Log "Checking git status..." "INFO"
    $gitStatus = git status --porcelain
    if ($gitStatus) {
        Log "Staging changes..." "INFO"
        git add -A
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Log "Committing changes..." "INFO"
        git commit -m "Build deployment: $timestamp - Frontend updates"
        Log "Pushing to origin main..." "INFO"
        git push origin main
        Log "Git push completed successfully" "INFO"
    } else {
        Log "No changes to commit" "INFO"
    }
} catch {
    Log "Git operation failed: $_" "ERROR"
}

# Netlify deployment hint
Log "=== Deployment Summary ===" "INFO"
Log "Frontend files ready in: $DestPath" "INFO"
Log "To deploy to Netlify:" "INFO"
Log "  1. Files in '$DestPath' are ready for deployment" "INFO"
Log "  2. Ensure 'netlify.toml' is in deploy folder" "INFO"
Log "  3. Use 'netlify deploy --prod' to push to production" "INFO"
Log "Backend: Already deployed at https://seekdata-backend.onrender.com" "INFO"