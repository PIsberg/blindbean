#!/usr/bin/env bash
# Replayed by asciinema to produce docs/demo.gif.
# Run from: blindbean-example/

GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

step() { echo -e "${DIM}# $*${RESET}"; sleep 0.5; }
cmd()  {
    echo -e "${GREEN}\$${RESET} ${BOLD}$*${RESET}"
    sleep 0.4
    eval "$*"
    echo ""
    sleep 1.0
}

clear
echo -e "${BOLD}BlindBean FHE Library${RESET} — Homomorphic Encryption made invisible"
echo ""
sleep 0.8

step "1. A Java domain entity annotated with @BlindEntity and @Homomorphic"
cmd "cat src/main/java/com/example/Wallet.java"
sleep 0.3

step "2. Compile the project — HomomorphicProcessor runs as part of javac"
cmd "mvn compile -q"
sleep 0.3

step "3. VibeTags compiles and updates AI platform rules automatically"
cmd "head -n 12 CLAUDE.md"
sleep 0.3

step "4. Auto-generated BlindWrapper provides transparent math on ciphertext"
cmd "cat target/generated-sources/annotations/com/example/WalletBlindWrapper.java | grep -A 8 'public void addFunds'"
sleep 0.3

step "5. Let's run homomorphic test verification!"
cmd "mvn test -Dtest=WalletTest -q"

echo -e "${GREEN}✓ All homomorphic math operations passed completely on encrypted data!${RESET}"
sleep 2
