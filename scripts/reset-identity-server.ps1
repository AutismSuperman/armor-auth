param(
    [string]$DbHost = "127.0.0.1",
    [int]$Port = 3306,
    [string]$Database = "identity_server",
    [string]$Username = "root",
    [string]$Password = "wangle",
    [switch]$KeepDatabase
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$schemaFile = Join-Path $repoRoot "armorauth-server\src\main\resources\sql\sas-schema.sql"
$dataFile = Join-Path $repoRoot "armorauth-server\src\main\resources\sql\sas-data.sql"

if (!(Test-Path $schemaFile)) {
    throw "Schema file not found: $schemaFile"
}

if (!(Test-Path $dataFile)) {
    throw "Data file not found: $dataFile"
}

$mysql = Get-Command mysql -ErrorAction SilentlyContinue
if (-not $mysql) {
    throw "mysql client not found in PATH. Please install MySQL/MariaDB client or add it to PATH."
}

$env:MYSQL_PWD = $Password

try {
    if (-not $KeepDatabase) {
        & $mysql.Source `
            --host=$DbHost `
            --port=$Port `
            --user=$Username `
            --default-character-set=utf8mb4 `
            --execute="DROP DATABASE IF EXISTS $Database; CREATE DATABASE $Database DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    }

    Get-Content $schemaFile | & $mysql.Source `
        --host=$DbHost `
        --port=$Port `
        --user=$Username `
        --database=$Database `
        --default-character-set=utf8mb4

    Get-Content $dataFile | & $mysql.Source `
        --host=$DbHost `
        --port=$Port `
        --user=$Username `
        --database=$Database `
        --default-character-set=utf8mb4
}
finally {
    Remove-Item Env:MYSQL_PWD -ErrorAction SilentlyContinue
}

Write-Output "Database '$Database' has been rebuilt from repository SQL."
