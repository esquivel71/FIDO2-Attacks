# Makefile to build all attacks.

# Usage:
#   make                (build all attacks)
#   make ATTACK_LOG=1   (build with attack logging enabled)
#   make DEBUG=1        (build with debug symbols)
#   make ATTACK_LOG=1 DEBUG=1 (build with both)
#   make clean          (clean all attack builds)

# --- Configuration ---
# Set to 1 to enable attack logging.
ATTACK_LOG ?= 0
# Set to 1 to enable debug symbols.
DEBUG ?= 0

# --- Build Logic ---
# Construct flags to pass to build scripts
BUILD_FLAGS =
ifeq ($(ATTACK_LOG),1)
    BUILD_FLAGS += -l
endif
ifeq ($(DEBUG),1)
    BUILD_FLAGS += -g
endif

.PHONY: all impersonation_attack rogue_key_attack double_register_attack clean

all: impersonation_attack rogue_key_attack double_register_attack

impersonation_attack:
	@echo ">>> Building ImpersonationAttack with flags: $(BUILD_FLAGS)"
	cd ImpersonationAttack && ./build_impersonation_attack.sh $(BUILD_FLAGS)

rogue_key_attack:
	@echo ">>> Building RogueKeyAttack with flags: $(BUILD_FLAGS)"
	cd RogueKeyAttack && ./build_rogue_key_attack.sh $(BUILD_FLAGS)

double_register_attack:
	@echo ">>> Building DoubleRegisterAttack with flags: $(BUILD_FLAGS)"
	cd DoubleRegisterAttack && ./build_double_register_attack.sh $(BUILD_FLAGS)

# Clean target to remove build artifacts.
clean:
	cd ./ImpersonationAttack && rm *.zip *.so
	cd ./RogueKeyAttack && rm *.zip *.so
	cd ./DoubleRegisterAttack && rm *.zip *.so
