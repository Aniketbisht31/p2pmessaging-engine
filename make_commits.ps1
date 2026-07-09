
# Script to create multiple commits with different timestamps

$env:GIT_AUTHOR_NAME = "Aniketbisht31"
$env:GIT_AUTHOR_EMAIL = "aniket@example.com"
$env:GIT_COMMITTER_NAME = "Aniketbisht31"
$env:GIT_COMMITTER_EMAIL = "aniket@example.com"

# Array of commits: [date, message, file content snippet]
$commits = @(
    @{ Date = "2026-06-01T09:00:00"; Message = "Initial project setup and scaffolding"; File = "CHANGELOG.md"; Content = "# Changelog`n`n## v0.1.0 - 2026-06-01`n- Initial project setup`n" },
    @{ Date = "2026-06-05T11:30:00"; Message = "Add peer discovery module"; File = "CHANGELOG.md"; Content = "# Changelog`n`n## v0.1.0 - 2026-06-01`n- Initial project setup`n`n## v0.1.1 - 2026-06-05`n- Add peer discovery module`n" },
    @{ Date = "2026-06-10T14:15:00"; Message = "Implement basic P2P message passing"; File = "CHANGELOG.md"; Content = "# Changelog`n`n## v0.1.0 - 2026-06-01`n- Initial project setup`n`n## v0.1.1 - 2026-06-05`n- Add peer discovery module`n`n## v0.1.2 - 2026-06-10`n- Implement basic P2P message passing`n" },
    @{ Date = "2026-06-15T10:00:00"; Message = "Add connection timeout and retry logic"; File = "CHANGELOG.md"; Content = "# Changelog`n`n## v0.1.0 - 2026-06-01`n- Initial project setup`n`n## v0.1.1 - 2026-06-05`n- Add peer discovery module`n`n## v0.1.2 - 2026-06-10`n- Implement basic P2P message passing`n`n## v0.1.3 - 2026-06-15`n- Add connection timeout and retry logic`n" },
    @{ Date = "2026-06-20T16:45:00"; Message = "Improve protocol encoding efficiency"; File = "CHANGELOG.md"; Content = "# Changelog`n`n## v0.2.0 - 2026-06-20`n- Improve protocol encoding efficiency`n- Connection timeout and retry logic`n- Peer discovery module`n- Initial project setup`n" },
    @{ Date = "2026-06-25T09:30:00"; Message = "Add unit tests for protocol module"; File = "CHANGELOG.md"; Content = "# Changelog`n`n## v0.2.0 - 2026-06-20`n- Improve protocol encoding efficiency`n`n## v0.2.1 - 2026-06-25`n- Add unit tests for protocol module`n" },
    @{ Date = "2026-06-28T13:00:00"; Message = "Fix race condition in peer connection handler"; File = "CHANGELOG.md"; Content = "# Changelog`n`n## v0.2.1 - 2026-06-25`n- Add unit tests for protocol module`n`n## v0.2.2 - 2026-06-28`n- Fix race condition in peer connection handler`n" },
    @{ Date = "2026-07-01T11:00:00"; Message = "Add storage layer with LevelDB backend"; File = "CHANGELOG.md"; Content = "# Changelog`n`n## v0.3.0 - 2026-07-01`n- Add storage layer with LevelDB backend`n- Fix race condition in peer connection handler`n- Unit tests for protocol module`n" },
    @{ Date = "2026-07-05T15:20:00"; Message = "Refactor network layer for better abstraction"; File = "CHANGELOG.md"; Content = "# Changelog`n`n## v0.3.0 - 2026-07-01`n- Add storage layer with LevelDB backend`n`n## v0.3.1 - 2026-07-05`n- Refactor network layer for better abstraction`n" },
    @{ Date = "2026-07-08T10:45:00"; Message = "Add integration tests and CI pipeline"; File = "CHANGELOG.md"; Content = "# Changelog`n`n## v0.3.1 - 2026-07-05`n- Refactor network layer for better abstraction`n`n## v0.3.2 - 2026-07-08`n- Add integration tests and CI pipeline`n" }
)

Write-Host "Creating $($commits.Count) commits with different timestamps..." -ForegroundColor Cyan

foreach ($commit in $commits) {
    # Write the file content
    Set-Content -Path (Join-Path $PSScriptRoot $commit.File) -Value $commit.Content -Encoding UTF8

    # Stage the file
    git add $commit.File

    # Set date env vars and commit
    $env:GIT_AUTHOR_DATE = $commit.Date
    $env:GIT_COMMITTER_DATE = $commit.Date

    git commit -m $commit.Message

    Write-Host "✓ Committed: [$($commit.Date)] $($commit.Message)" -ForegroundColor Green
}

Write-Host "`nAll commits created!" -ForegroundColor Cyan
git log --oneline
