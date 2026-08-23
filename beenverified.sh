#!/bin/bash
# BeenVerified Offline Database Access - Shell Wrapper
# Convenience wrapper around the Python script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/beenverified_offline_access.py"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Python script exists
if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo -e "${RED}Error: beenverified_offline_access.py not found${NC}"
    exit 1
fi

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required${NC}"
    exit 1
fi

# Parse arguments
case "$1" in
    setup)
        shift
        python3 "$PYTHON_SCRIPT" setup "$@"
        ;;
    sync)
        shift
        echo -e "${YELLOW}Starting sync...${NC}"
        python3 "$PYTHON_SCRIPT" sync "$@"
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
        echo "BeenVerified Offline Database Access"
        echo ""
        echo "Usage: $(basename "$0") <command> [options]"
        echo ""
        echo "Commands:"
        echo "  setup   <--email EMAIL>              Setup your BeenVerified account"
        echo "  sync    <--email EMAIL>              Download all purchased records"
        echo "  search  <--email EMAIL --query TEXT> Search offline database"
        echo "  stats   <--email EMAIL>              Show account statistics"
        echo ""
        echo "Examples:"
        echo "  $(basename "$0") setup --email you@example.com"
        echo "  $(basename "$0") sync --email you@example.com"
        echo "  $(basename "$0") search --email you@example.com --query 'John Doe'"
        echo "  $(basename "$0") stats --email you@example.com"
        echo ""
        echo "For full documentation, see BEENVERIFIED_OFFLINE_GUIDE.md"
        ;;
    *)
        if [ -z "$1" ]; then
            echo -e "${YELLOW}No command specified. Use 'help' for usage.${NC}"
            exit 0
        else
            echo -e "${RED}Unknown command: $1${NC}"
            echo "Use 'help' for usage"
            exit 1
        fi
        ;;
esac
