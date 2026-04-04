# Root Makefile for Qchaves
# Redirects all build commands to the Modulos directory
# and manages symbolic links in the root folder.

.PHONY: all address bsgs kangaroo clean links

all:
	@$(MAKE) -C Modulos all
	@$(MAKE) links

address:
	@$(MAKE) -C Modulos address
	@ln -sf Modulos/Address/modo-address .

bsgs:
	@$(MAKE) -C Modulos bsgs
	@ln -sf Modulos/BSGS/modo-bsgs .

kangaroo:
	@$(MAKE) -C Modulos kangaroo
	@ln -sf Modulos/kangaroo/modo-kangaroo .

links:
	@ln -sf Modulos/Address/modo-address .
	@ln -sf Modulos/BSGS/modo-bsgs .
	@ln -sf Modulos/kangaroo/modo-kangaroo .
	@echo "[+] Root symbolic links refreshed."

clean:
	@$(MAKE) -C Modulos clean
	@rm -f modo-address modo-bsgs modo-kangaroo

# Catch-all for other targets
%:
	@$(MAKE) -C Modulos $@
