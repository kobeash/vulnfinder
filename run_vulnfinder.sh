#!/bin/bash
# run_vulnfinder.sh

# Use local deps folder
PYTHONPATH="$(pwd)/deps" python3 vulnfinder.py "$@"
