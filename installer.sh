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
HASHES_FILE="$SCRIPT_DIR/hashes.json"
DEPS_FILE="$SCRIPT_DIR/dependencies.json"
SOURCE_DIR="$SCRIPT_DIR/scripts"

# ── Header ───────────────────────────────────────────────────────
print_header() {
    echo ""
    # ── Upper Red Part ─────────────────────────────
    echo -e "${RED}"
cat << "EOF"
                          ...*#=..                    
                            ..--:+..                    
                            ..:*#...                    
                              .%+                       
                             .:%=                       
                            ..-@-                       
                            ..+@.                       
                            ..*@.                       
                         ....-**.....                   
                         ....=#+....                    
                       ..-=-=#%#......                  
                         .:*%%##%%+:.                   
                         ...-*#@:....                   
                         ...:=%......                   
                         ...-#+.....                    
                         ...*##.....                    
                         ..:#%%.....                    
                         ...=%-                         
                         ...*+.                         
                         ..=**.                         
                         ..+*#:                         
                         ..+*%.                         
                    .......++#.                         
                    ......:+*+.                         
                    ...=..-+#-.                         
                   ....+..++#:.                         
                   ..+*-..*+#..                         
                   .:+:...**#..                         
                   .:+...-***..                         
                   .:+==:-*#+..                         
                  ..:=+***+#+:......                    
                  ..=+*+*#+#*.......                    
                  ...*+*++#**-.-....                    
EOF
    # ── Lower Yellow Part ──────────────────────────
    echo -e "${YELLOW}"
cat << "EOF"
               .....=:++*+*+*::+.....                   
               ....-+:+++++==++=....                    
               ...:*++++*=++*+++*-..                    
             ......=**=++++++++++#:......               
            ...-*:=#+*+*#+-+++++*#*==+=....             
              ..*#%**=++==*+++****+#%*=#%...            
       .......=**+++=++=-++#*++*#==*#*#%=*+=:....       
        ..===***+=+=++====++=++*+++***###+=%@#-..       
          .-**-++=+++===++++==**=+**=**#**#:*.-*.       
.......=+***==++:-=+==+==+=++***++=*+*#*=*#%@@@###*.....
..=##*+---=**+=++====+++++**#####+=++#%#++*%%%@%%#%%%#+.
.:###***+*+==-==+******+====+==+++++*##*==+#***+++*#%##*
.-%##*++*++==============-=====+++++++++=+*%#***#%%%@@@#
.+@%%####****+*****#**#####**#%%####*#%%%%%@@@@@@@@@@@@#
.:%@%%%%%####*********####%%%%%%%%%@@@@@@@@@@@@@@@@@@@%-
....:*%%%%%%############%%%%%%@@@@@@@@@@@@@@@@@@%#=.....
     .........:-=+**#%@@@@@@@@@@@#*+=-:...........
EOF

    echo -e "${NC}"
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

# SHA256 of a single file
hash_file() {
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

# SHA256 of sorted direct-children file hashes
# mirrors exactly what generate_hashes.py does
hash_folder() {
    local folder="$1"
    local combined=""
    local file_hashes=()

    # collect hashes of direct children files only
    # sorted by filename — same as Python's sorted(folder.iterdir())
    while IFS= read -r -d '' f; do
        # skip .pyc and hidden files
        local basename
        basename=$(basename "$f")
        [[ "$basename" == .* ]]         && continue
        [[ "$basename" == *.pyc ]]      && continue
        [[ "$basename" == *.pyo ]]      && continue
        file_hashes+=("$(hash_file "$f")")
    done < <(find "$folder" -maxdepth 1 -type f -print0 | sort -z)

    # sort the hashes and concatenate
    local sorted_combined
    sorted_combined=$(printf '%s' "${file_hashes[@]}" | \
                      fold -w 64 | sort | tr -d '\n')

    # SHA256 of the combined string
    echo -n "$sorted_combined" | sha256sum | awk '{print $1}'
}

# ── Step 1: Hash validation ───────────────────────────────────────
validate_hashes() {
    log_section "Step 1 — Integrity Check"

    if [ ! -f "$HASHES_FILE" ]; then
        log_err "hashes.json not found at $HASHES_FILE"
        exit 1
    fi

    local corrupted=()

    # ── verify root-level files ───────────────────────────────────
    local root_file_count
    root_file_count=$(jq '[.entries[] | select(.type=="file" and .parent=="/")] | length' "$HASHES_FILE")

    for i in $(seq 0 $((root_file_count - 1))); do
        local name expected actual path

        name=$(jq -r ".entries[] | select(.type==\"file\" and .parent==\"/\") | \
               .name" "$HASHES_FILE" | sed -n "$((i+1))p")
        expected=$(jq -r ".entries[] | select(.type==\"file\" and .parent==\"/\" \
               and .name==\"$name\") | .hash" "$HASHES_FILE")
        path="$SCRIPT_DIR/$name"

        if [ ! -f "$path" ]; then
            log_err "Missing: $name"
            corrupted+=("$name (missing)")
            continue
        fi

        actual=$(hash_file "$path")
        if [ "$actual" = "$expected" ]; then
            log_ok "OK: $name"
        else
            log_err "Corrupted: $name"
            corrupted+=("$name (hash mismatch)")
        fi
    done

    # ── verify folders ────────────────────────────────────────────
    local folder_names
    mapfile -t folder_names < <(jq -r '.entries[] | select(.type=="folder") | .name' "$HASHES_FILE")

    for folder_name in "${folder_names[@]}"; do
        local expected parent folder_path actual

        expected=$(jq -r --arg n "$folder_name" \
            '.entries[] | select(.type=="folder" and .name==$n) | .hash' \
            "$HASHES_FILE")
        parent=$(jq -r --arg n "$folder_name" \
            '.entries[] | select(.type=="folder" and .name==$n) | .parent' \
            "$HASHES_FILE")

        # resolve folder path
        if [ "$parent" = "/" ]; then
            folder_path="$SCRIPT_DIR/$folder_name"
        else
            # find parent folder path
            local parent_parent
            parent_parent=$(jq -r --arg n "$parent" \
                '.entries[] | select(.type=="folder" and .name==$n) | .parent' \
                "$HASHES_FILE")
            if [ "$parent_parent" = "/" ]; then
                folder_path="$SCRIPT_DIR/$parent/$folder_name"
            else
                folder_path="$SCRIPT_DIR/$parent_parent/$parent/$folder_name"
            fi
        fi

        if [ ! -d "$folder_path" ]; then
            log_err "Missing folder: $folder_name"
            corrupted+=("$folder_name/ (folder missing)")
            continue
        fi

        actual=$(hash_folder "$folder_path")

        if [ "$actual" = "$expected" ]; then
            log_ok "Folder OK: $folder_name/"
        else
            log_warn "Folder mismatch: $folder_name/ — checking files..."

            # drill into folder — check each file individually
            local file_names
            mapfile -t file_names < <(jq -r --arg p "$folder_name" \
                '.entries[] | select(.type=="file" and .parent==$p) | .name' \
                "$HASHES_FILE")

            for file_name in "${file_names[@]}"; do
                local f_expected f_actual f_path

                f_expected=$(jq -r --arg n "$file_name" --arg p "$folder_name" \
                    '.entries[] | select(.type=="file" and .name==$n and .parent==$p) | .hash' \
                    "$HASHES_FILE")
                f_path="$folder_path/$file_name"

                if [ ! -f "$f_path" ]; then
                    log_err "  Missing: $folder_name/$file_name"
                    corrupted+=("$folder_name/$file_name (missing)")
                    continue
                fi

                f_actual=$(hash_file "$f_path")
                if [ "$f_actual" = "$f_expected" ]; then
                    log_ok "  OK: $file_name"
                else
                    log_err "  Corrupted: $file_name"
                    corrupted+=("$folder_name/$file_name (hash mismatch)")
                fi
            done
        fi
    done

    # ── report ────────────────────────────────────────────────────
    echo ""
    if [ ${#corrupted[@]} -gt 0 ]; then
        log_err "Integrity check FAILED. Corrupted or missing files:"
        echo ""
        for entry in "${corrupted[@]}"; do
            echo -e "  ${RED}  → $entry${NC}"
        done
        echo ""
        log_err "Installation aborted. Restore the files and try again."
        exit 1
    else
        log_ok "All files verified successfully."
    fi
}

check_unknown_files() {
    log_section "Step 1b — Unknown File Check"

    local unknown=()

    # folders to scan
    local scan_dirs=(
        "$SCRIPT_DIR/scripts/main"
        "$SCRIPT_DIR/scripts/main/ebpf"
        "$SCRIPT_DIR/scripts/main/workers"
        "$SCRIPT_DIR/scripts/rules"
    )

    for dir in "${scan_dirs[@]}"; do
        [ ! -d "$dir" ] && continue
        local folder_name
        folder_name=$(basename "$dir")

        while IFS= read -r -d '' f; do
            local filename
            filename=$(basename "$f")

            # skip hidden and compiled files
            [[ "$filename" == .* ]]     && continue
            [[ "$filename" == *.pyc ]]  && continue
            [[ "$filename" == *.pyo ]]  && continue

            # check if this file exists in hashes.json
            local known
            known=$(jq -r --arg n "$filename" --arg p "$folder_name" \
                '.entries[] | select(.name==$n and .parent==$p) | .name' \
                "$HASHES_FILE")

            if [ -z "$known" ]; then
                log_warn "Unknown file not in manifest: $folder_name/$filename"
                unknown+=("$folder_name/$filename")
            fi

        done < <(find "$dir" -maxdepth 1 -type f -print0)
    done

    # also check root level
    while IFS= read -r -d '' f; do
        local filename
        filename=$(basename "$f")

        # skip known non-script files
        [[ "$filename" == "installer.sh" ]]       && continue
        [[ "$filename" == "generate_hashes.py" ]] && continue
        [[ "$filename" == "hashes.json" ]]        && continue
        [[ "$filename" == "README.md" ]]           && continue
        [[ "$filename" == .* ]]                    && continue

        local known
        known=$(jq -r --arg n "$filename" \
            '.entries[] | select(.name==$n and .parent=="/") | .name' \
            "$HASHES_FILE")

        if [ -z "$known" ]; then
            log_warn "Unknown file not in manifest: $filename"
            unknown+=("$filename")
        fi

    done < <(find "$SCRIPT_DIR" -maxdepth 1 -type f -print0)

    echo ""
    if [ ${#unknown[@]} -gt 0 ]; then
        log_err "Unknown files found that are not in the integrity manifest:"
        echo ""
        for entry in "${unknown[@]}"; do
            echo -e "  ${RED}  → $entry${NC}"
        done
        echo ""
        echo -e "  ${YELLOW}  These files were not present when hashes.json was generated.${NC}"
        echo -e "  ${YELLOW}  If you added them intentionally, run generate_hashes.py first.${NC}"
        echo ""
        log_err "Installation aborted."
        exit 1
    else
        log_ok "No unknown files detected."
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
    archive)
    sudo python3 "$SCRIPT_DIR/archive_viewer.py"
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
    echo -e "  ${CYAN}  sudo bonfire archive${NC}"  
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
    check_unknown_files 
    install_dependencies
    copy_files
    create_wrapper
    print_done
}

main
