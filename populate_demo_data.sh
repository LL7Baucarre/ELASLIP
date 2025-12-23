#!/bin/bash
# Demo data population script for ElasMISP
# Usage: ./populate_demo_data.sh

cd "$(dirname "$0")/.." || exit 1

echo "ElasMISP Demo Data Population"
echo "============================="
echo ""

# Check if environment file exists
if [ ! -f .env ]; then
    echo "Error: .env file not found!"
    echo "Please create a .env file with DEMO_DATA_ENABLED=true"
    exit 1
fi

# Run the demo data script
python scripts/demo_data.py

exit $?
