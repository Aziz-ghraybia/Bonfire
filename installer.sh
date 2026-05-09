#!/bin/bash

# ── Colors ───────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
NC='\033[0m'

# ── Paths ─────────────────────────────────────────────────────────
INSTALL_DIR="/opt/bonfire"
BIN_PATH="/usr/local/bin/bonfire"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HASHES_FILE="$SCRIPT_DIR/hash.json"
DEPS_FILE="$SCRIPT_DIR/dependencies.json"
SOURCE_DIR="$SCRIPT_DIR/scripts"

# ── Header ───────────────────────────────────────────────────────
print_header() {
    echo ""
    echo -e "${RED}    🔥 BONFIRE INSTALLER${NC}"
    echo -e "${DIM}    Kernel Behavior Monitor · eBPF IDS${NC}"
    echo ""
    echo -e "${DIM}    ─────────────────────────────────────${NC}"
    echo ""
}

# ── Logging ──────────────────────────────────────────────────────
log_info()    { echo -e "  ${CYAN}[*]${NC} $1"; }
log_ok()      { echo -e "  ${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "  ${YELLOW}[!]${NC} $1"; }
log_err()     { echo -e "  ${RED}[✗]${NC} $1"; }
log_section() { echo -e "\n  ${WHITE}$1${NC}\n  ${DIM}$(printf '─%.0s' {1..40})${NC}"; }

# ── Root check ───────────────────────────────────────────────────
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_err "Installer must be run as root."
        echo -e "  ${DIM}Run: sudo bash installer.sh${NC}"
        exit 1
    fi
}

# ── Dependency check ─────────────────────────────────────────────
check_deps() {
    for cmd in python3 sha256sum jq; do
        if ! command -v "$cmd" &>/dev/null; then
            log_err "Required tool not found: $cmd"
            echo -e "  ${DIM}Install it with: apt-get install -y $cmd${NC}"
            exit 1
        fi
    done
}

# ── Hash helpers ─────────────────────────────────────────────────

# compute sha256 of a single file
hash_file() {
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

# compute combined hash of all files inside a folder (recursive, sorted)
hash_folder() {
    find "$1" -type f | sort | xargs sha256sum 2>/dev/null | sha256sum | awk '{print $1}'
}

# resolve full path from hashes.json entry
resolve_path() {
    local name="$1"
    local parent="$2"

    if [ "$parent" = "/" ]; then
        echo "$SCRIPT_DIR/$name"
    else
        # find parent path by traversing the tree
        local parent_path
        parent_path=$(resolve_entry_path "$parent")
        echo "$parent_path/$name"
    fi
}

# get the full path of an entry by its name
resolve_entry_path() {
    local entry_name="$1"
    local parent
    parent=$(jq -r --arg n "$entry_name" \
        '.entries[] | select(.name == $n) | .parent' "$HASHES_FILE")

    if [ "$parent" = "/" ]; then
        echo "$SCRIPT_DIR/$entry_name"
    else
        local parent_path
        parent_path=$(resolve_entry_path "$parent")
        echo "$parent_path/$entry_name"
    fi
}

# ── Step 1: Hash validation ──────────────────────────────────────
validate_hashes() {
    log_section "Step 1 — Integrity Check"

    if [ ! -f "$HASHES_FILE" ]; then
        log_err "hashes.json not found at $HASHES_FILE"
        exit 1
    fi

    local corrupted=()
    local checked=0
    local skipped=0

    # get all folder entries
    local folders
    folders=$(jq -r '.entries[] | select(.type == "folder") | .name' "$HASHES_FILE")

    for folder in $folders; do
        local expected_hash
        expected_hash=$(jq -r --arg n "$folder" \
            '.entries[] | select(.name == $n) | .hash' "$HASHES_FILE")

        local folder_path
        folder_path=$(resolve_entry_path "$folder")

        if [ ! -d "$folder_path" ]; then
            log_err "Folder not found: $folder_path"
            corrupted+=("$folder (folder missing)")
            continue
        fi

        local actual_hash
        actual_hash=$(hash_folder "$folder_path")

        if [ "$actual_hash" = "$expected_hash" ]; then
            log_ok "Folder OK: $folder"
            ((skipped++))
        else
            log_warn "Folder mismatch: $folder — checking files inside..."

            # drill into folder — check each file that belongs to it
            local file_entries
            file_entries=$(jq -r --arg p "$folder" \
                '.entries[] | select(.type == "file" and .parent == $p) | .name' \
                "$HASHES_FILE")

            for file in $file_entries; do
                local expected_file_hash
                expected_file_hash=$(jq -r --arg n "$file" \
                    '.entries[] | select(.name == $n) | .hash' "$HASHES_FILE")

                local file_path="$folder_path/$file"

                if [ ! -f "$file_path" ]; then
                    log_err "  File missing: $file"
                    corrupted+=("$folder/$file (missing)")
                    continue
                fi

                local actual_file_hash
                actual_file_hash=$(hash_file "$file_path")
                ((checked++))

                if [ "$actual_file_hash" = "$expected_file_hash" ]; then
                    log_ok "  File OK: $file"
                else
                    log_err "  File corrupted: $file"
                    corrupted+=("$folder/$file (hash mismatch)")
                fi
            done
        fi
    done

    # also check root-level files
    local root_files
    root_files=$(jq -r '.entries[] | select(.type == "file" and .parent == "/") | .name' \
        "$HASHES_FILE")

    for file in $root_files; do
        local expected_hash
        expected_hash=$(jq -r --arg n "$file" \
            '.entries[] | select(.name == $n) | .hash' "$HASHES_FILE")

        local file_path="$SCRIPT_DIR/$file"

        if [ ! -f "$file_path" ]; then
            log_err "File missing: $file"
            corrupted+=("$file (missing)")
            continue
        fi

        local actual_hash
        actual_hash=$(hash_file "$file_path")
        ((checked++))

        if [ "$actual_hash" = "$expected_hash" ]; then
            log_ok "File OK: $file"
        else
            log_err "File corrupted: $file"
            corrupted+=("$file (hash mismatch)")
        fi
    done

    # report
    echo ""
    if [ ${#corrupted[@]} -gt 0 ]; then
        log_err "Integrity check failed. Corrupted files:"
        echo ""
        for entry in "${corrupted[@]}"; do
            echo -e "  ${RED}  → $entry${NC}"
        done
        echo ""
        log_err "Installation aborted. Please restore the corrupted files."
        exit 1
    else
        log_ok "All files verified successfully."
    fi
}

# ── Step 2: Install dependencies ────────────────────────────────
install_dependencies() {
    log_section "Step 2 — Dependencies"

    if [ ! -f "$DEPS_FILE" ]; then
        log_err "dependencies.json not found at $DEPS_FILE"
        exit 1
    fi

    local dep_count
    dep_count=$(jq '.dependencies | length' "$DEPS_FILE")

    for i in $(seq 0 $((dep_count - 1))); do
        local name env cmd verify required

        name=$(jq -r ".dependencies[$i].name" "$DEPS_FILE")
        env=$(jq -r ".dependencies[$i].environment" "$DEPS_FILE")
        cmd=$(jq -r ".dependencies[$i].command" "$DEPS_FILE")
        verify=$(jq -r ".dependencies[$i].verify_command // empty" "$DEPS_FILE")
        required=$(jq -r ".dependencies[$i].required" "$DEPS_FILE")

        # if verify command exists — check first
        if [ -n "$verify" ]; then
            if eval "$verify" &>/dev/null; then
                log_ok "Already installed: $name"
                continue
            fi
        fi

        log_info "Installing: $name ($env)"

        # run install command
        if eval "$cmd" &>/dev/null; then
            log_ok "Installed: $name"
        else
            if [ "$required" = "true" ]; then
                log_err "Failed to install required dependency: $name"
                log_err "Installation aborted."
                exit 1
            else
                log_warn "Failed to install optional dependency: $name"
            fi
        fi
    done

    log_ok "All dependencies installed."
}

# ── Step 3: Copy files ───────────────────────────────────────────
copy_files() {
    log_section "Step 3 — Installing Files"

    # create destination
    if [ -d "$INSTALL_DIR" ]; then
        log_warn "/opt/bonfire already exists — overwriting."
        rm -rf "$INSTALL_DIR"
    fi

    mkdir -p "$INSTALL_DIR"
    log_ok "Created $INSTALL_DIR"

    # copy scripts folder
    cp -r "$SOURCE_DIR" "$INSTALL_DIR/scripts"
    log_ok "Copied scripts/ → $INSTALL_DIR/scripts/"

    # set permissions
    chown -R root:root "$INSTALL_DIR"
    chmod -R 755 "$INSTALL_DIR"
    log_ok "Permissions set."
}

# ── Step 4: Create shell wrapper ─────────────────────────────────
create_wrapper() {
    log_section "Step 4 — Creating bonfire command"

    cat > "$BIN_PATH" << 'WRAPPER'
#!/bin/bash

SCRIPT_DIR="/opt/bonfire/scripts/main"

case "$1" in
    dashboard)
        sudo python3 "$SCRIPT_DIR/cli.py"
        ;;
    monitor)
        sudo python3 "$SCRIPT_DIR/monitor.py"
        ;;
    alerts)
        sudo python3 "$SCRIPT_DIR/alerts_viewer.py"
        ;;
    rules)
        sudo python3 "$SCRIPT_DIR/rules_viewer.py"
        ;;
    rules-add)
        sudo python3 "$SCRIPT_DIR/rule_add.py"
        ;;
    help|--help|-h|"")
        echo ""
        echo "  🔥 BONFIRE — Kernel Behavior Monitor"
        echo ""
        echo "  Usage: bonfire <command>"
        echo ""
        echo "  Commands:"
        echo "    dashboard    Launch live terminal dashboard"
        echo "    monitor      Standalone terminal mode"
        echo "    alerts       Alert inspector"
        echo "    rules        Rules viewer"
        echo "    rules-add    Add a new detection rule (root only)"
        echo "    help         Show this help message"
        echo ""
        echo "  Examples:"
        echo "    sudo bonfire dashboard"
        echo "    sudo bonfire alerts"
        echo "    sudo bonfire rules"
        echo "    sudo bonfire rules-add"
        echo ""
        echo "  Version: 0.1.0"
        echo "  Location: /opt/bonfire/"
        echo ""
        ;;
    *)
        echo "  Unknown command: $1"
        echo "  Run 'bonfire help' for usage."
        exit 1
        ;;
esac
WRAPPER

    chmod +x "$BIN_PATH"
    log_ok "Created $BIN_PATH"
}

# ── Done ─────────────────────────────────────────────────────────
print_done() {
    echo ""
    echo -e "  ${DIM}─────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${GREEN}🔥 Bonfire installed successfully!${NC}"
    echo ""
    echo -e "  ${DIM}Available commands:${NC}"
    echo -e "  ${CYAN}  sudo bonfire dashboard${NC}"
    echo -e "  ${CYAN}  sudo bonfire monitor${NC}"
    echo -e "  ${CYAN}  sudo bonfire alerts${NC}"
    echo -e "  ${CYAN}  sudo bonfire rules${NC}"
    echo -e "  ${CYAN}  sudo bonfire rules-add${NC}"
    echo ""
    echo -e "  ${DIM}Installed to: $INSTALL_DIR${NC}"
    echo -e "  ${DIM}Command at:   $BIN_PATH${NC}"
    echo ""
}

# ── Entry point ──────────────────────────────────────────────────
main() {
    print_header
    check_root
    check_deps
    validate_hashes
    install_dependencies
    copy_files
    create_wrapper
    print_done
}

main
