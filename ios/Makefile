#-------------------------------------------------------------------------------
.SUFFIXES:
#-------------------------------------------------------------------------------

.PHONY: all clean ios_kernel ios_mcp ios_net

all: ios_kernel
	@echo "\033[92mDone!\033[0m"

ios_net:
	@echo "\033[92mBuilding $@...\033[0m"
	@$(MAKE) --no-print-directory -C $(CURDIR)/ios_net

ios_mcp:
	@echo "\033[92mBuilding $@...\033[0m"
	@$(MAKE) --no-print-directory -C $(CURDIR)/ios_mcp

ios_kernel: ios_net ios_mcp
	@echo "\033[92mBuilding $@...\033[0m"
	@$(MAKE) --no-print-directory -C $(CURDIR)/ios_kernel

clean:
	@echo "\033[92mCleaning $@...\033[0m"
	@$(MAKE) --no-print-directory -C $(CURDIR)/ios_net clean
	@$(MAKE) --no-print-directory -C $(CURDIR)/ios_mcp clean
	@$(MAKE) --no-print-directory -C $(CURDIR)/ios_kernel clean
