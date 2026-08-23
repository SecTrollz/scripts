#!/bin/bash
# BeenVerified Full Database Access
# For accounts with complete dataset purchased access

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/beenverified_full_database.py"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo -e "${RED}Error: beenverified_full_database.py not found${NC}"
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
    verify)
        shift
        echo -e "${CYAN}🔐 Verifying Full Database Access${NC}"
        echo -e "${CYAN}📊 This will check your contract for complete dataset access${NC}"
        echo ""
        python3 "$PYTHON_SCRIPT" verify "$@"
        ;;
    search)
        shift
        python3 "$PYTHON_SCRIPT" search "$@"
        ;;
    stats)
        shift
        python3 "$PYTHON_SCRIPT" stats "$@"
        ;;
    compress)
        shift
        echo -e "${BLUE}📦 Compressing database for archival storage${NC}"
        python3 "$PYTHON_SCRIPT" compress "$@"
        ;;
    license)
        shift
        python3 "$PYTHON_SCRIPT" license "$@"
        ;;
    help|--help|-h)
        echo -e "${GREEN}BeenVerified Full Database Access${NC}"
        echo -e "${CYAN}For accounts with complete dataset purchase${NC}"
        echo ""
        echo "Usage: $(basename "$0") <command> [options]"
        echo ""
        echo "Commands:"
        echo -e "  ${BLUE}verify${NC} [--headless true/false]"
        echo "      Verify full database access (one-time setup)"
        echo ""
        echo -e "  ${BLUE}search${NC} --query TEXT [--type TYPE]"
        echo "      Search full database"
        echo "      Types: name (default), phone, email, address, state"
        echo ""
        echo -e "  ${BLUE}stats${NC}"
        echo "      Show database statistics and size"
        echo ""
        echo -e "  ${BLUE}compress${NC}"
        echo "      Compress database for archival storage"
        echo ""
        echo -e "  ${BLUE}license${NC}"
        echo "      Show license information"
        echo ""
        echo "Examples:"
        echo "  $(basename "$0") verify"
        echo "  $(basename "$0") search --query 'John Doe'"
        echo "  $(basename "$0") search --query '555-1234' --type phone"
        echo "  $(basename "$0") search --query 'New York' --type address"
        echo "  $(basename "$0") stats"
        echo "  $(basename "$0") compress"
        echo ""
        echo "Features:"
        echo "  ✅ Full database access verification"
        echo "  ✅ Multi-field search (name, phone, email, address, state)"
        echo "  ✅ Indexed search (500+ results per query)"
        echo "  ✅ Database compression for storage"
        echo "  ✅ License tracking and verification"
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
