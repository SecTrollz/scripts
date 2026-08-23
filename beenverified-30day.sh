#!/bin/bash
# BeenVerified 30-Day Full Database Access
# Complete database with automatic expiration and deletion

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/beenverified_30day_access.py"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
ORANGE='\033[0;33m'
NC='\033[0m'

if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo -e "${RED}Error: beenverified_30day_access.py not found${NC}"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required${NC}"
    exit 1
fi

if ! command -v firefox &> /dev/null; then
    echo -e "${RED}Error: Firefox is required${NC}"
    exit 1
fi

python3 -c "import playwright" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Installing Playwright...${NC}"
    pip3 install playwright > /dev/null 2>&1
    python3 -m playwright install firefox
fi

case "$1" in
    download)
        shift
        echo -e "${ORANGE}⏱️  BeenVerified 30-Day Full Database Access${NC}"
        echo -e "${ORANGE}📥 Download starts your 30-day countdown${NC}"
        echo ""
        python3 "$PYTHON_SCRIPT" download "$@"
        ;;
    search)
        shift
        python3 "$PYTHON_SCRIPT" search "$@"
        ;;
    status)
        shift
        python3 "$PYTHON_SCRIPT" status "$@"
        ;;
    check)
        shift
        python3 "$PYTHON_SCRIPT" check "$@"
        ;;
    help|--help|-h)
        echo -e "${GREEN}BeenVerified 30-Day Full Database Access${NC}"
        echo -e "${ORANGE}Complete dataset with time-limited offline access${NC}"
        echo ""
        echo "Contract: Full database access for 30 days"
        echo "Timer: Starts when download completes"
        echo "Auto-delete: Database removed at expiration"
        echo ""
        echo "Usage: $(basename "$0") <command> [options]"
        echo ""
        echo "Commands:"
        echo -e "  ${BLUE}download${NC} [--headless true/false]"
        echo "      Download full database and activate 30-day timer"
        echo ""
        echo -e "  ${BLUE}search${NC} --query TEXT [--type TYPE]"
        echo "      Search database during 30-day window"
        echo "      Types: name (default), phone, email, address, state"
        echo ""
        echo -e "  ${BLUE}status${NC}"
        echo "      Show remaining time and database stats"
        echo ""
        echo -e "  ${BLUE}check${NC}"
        echo "      Quick check if access is still valid"
        echo ""
        echo "Examples:"
        echo "  $(basename "$0") download              # Download and start timer"
        echo "  $(basename "$0") status                # Check time remaining"
        echo "  $(basename "$0") search --query 'John Doe'"
        echo "  $(basename "$0") search --query '555-1234' --type phone"
        echo "  $(basename "$0") check                 # Is access still valid?"
        echo ""
        echo "How it works:"
        echo "  1. Run 'download' to fetch full database"
        echo "  2. 30-day timer STARTS when download completes"
        echo "  3. Use 'search' to query during the 30 days"
        echo "  4. Use 'status' to see remaining time"
        echo "  5. At day 30: database auto-deletes"
        echo ""
        echo "Features:"
        echo "  ✅ Full database download"
        echo "  ✅ 30-day offline access"
        echo "  ✅ Automatic expiration"
        echo "  ✅ Auto-delete on expire"
        echo "  ✅ Countdown timer"
        echo "  ✅ Multi-field search"
        ;;
    *)
        if [ -z "$1" ]; then
            echo -e "${YELLOW}No command specified${NC}"
        else
            echo -e "${RED}Unknown command: $1${NC}"
        fi
        echo "Use 'help' for usage"
        exit 1
        ;;
esac
