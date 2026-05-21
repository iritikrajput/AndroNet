param([Parameter(Mandatory)][string]$Version)

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
  Write-Error "Version must be in format X.Y.Z (e.g. 1.0.0)"
  exit 1
}

$tag = "v$Version"

Write-Host "Creating release $tag..." -ForegroundColor Green

git tag -a $tag -m "Release $tag"
git push origin $tag

Write-Host "Tag $tag pushed. GitHub Actions will now build and publish the APK." -ForegroundColor Green
Write-Host "Monitor progress at: https://github.com/amibhai/AndroNet/actions" -ForegroundColor Cyan
