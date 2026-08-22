#!/bin/bash
# BeenVerified Browser-Based Sync - Shell Wrapper
# Uses Firefox with overlay status monitor

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/beenverified_browser_sync.py"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check requirements
if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo -e "${RED}Error: beenverified_browser_sync.py not found${NC}"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required${NC}"
    exit 1
fi

if ! command -v firefox &> /dev/null; then
    echo -e "${RED}Error: Firefox is required. Install with: apt install firefox${NC}"
    exit 1
fi

# Check for Playwright
python3 -c "import playwright" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}Installing Playwright...${NC}"
    pip3 install playwright > /dev/null 2>&1
    python3 -m playwright install firefox
fi

case "$1" in
    sync)
        shift
        echo -e "${BLUE}🚀 Starting BeenVerified browser sync${NC}"
        echo -e "${BLUE}📱 Firefox will open with status overlay${NC}"
        echo ""
        python3 "$PYTHON_SCRIPT" sync "$@"
        ;;
    sync-headless)
        shift
        echo -e "${BLUE}🚀 Starting headless sync${NC}"
        python3 "$PYTHON_SCRIPT" sync --headless true "$@"
        ;;
    search)
        shift
        python3 "$PYTHON_SCRIPT" search "$@"
        ;;
    stats)
        shift
        python3 "$PYTHON_SCRIPT" stats "$@"
        ;;
    help|--help|-h)
        echo -e "${GREEN}BeenVerified Browser-Based Sync${NC}"
        echo ""
        echo "Usage: $(basename "$0") <command> [options]"
        echo ""
        echo "Commands:"
        echo -e "  ${BLUE}sync${NC} [--headless true/false] [--max-chunks N]"
        echo "      Start browser sync (Firefox opens with overlay)"
        echo ""
        echo -e "  ${BLUE}sync-headless${NC} [--max-chunks N]"
        echo "      Run sync in background (no GUI)"
        echo ""
        echo -e "  ${BLUE}search${NC} --query TEXT"
        echo "      Search indexed database"
        echo ""
        echo -e "  ${BLUE}stats${NC}"
        echo "      Show sync statistics"
        echo ""
        echo "Examples:"
        echo "  $(basename "$0") sync"
        echo "  $(basename "$0") sync --max-chunks 50"
        echo "  $(basename "$0") sync-headless"
        echo "  $(basename "$0") search --query 'John Doe'"
        echo "  $(basename "$0") stats"
        echo ""
        echo "Features:"
        echo "  ✅ Real browser authentication (Firefox)"
        echo "  ✅ Overlay status monitor"
        echo "  ✅ Chunk-based downloading"
        echo "  ✅ Automatic indexing"
        echo "  ✅ No activity logging"
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
