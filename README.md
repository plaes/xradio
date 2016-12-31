Allwinner xr819 driver to cw1200 driver port
============================================

* ap.[ch] - missing from cw1200
* bh.[ch]
* common.[ch] - missing from cw1200
* cw1200.h
* cw1200_sdio.c
* debug.[ch]
* fwio.[ch]
* ht.h
* hwbus.h
* hwio.[ch]
* itp.[ch] - missing, ITP debug subsystem (removed from cw1200, see commit fa8eeae102570dfdf3fd14347a0671cff8a2cfe4)
* Kconfig
* main.c
* Makefile
* nl80211_testmode_msg_copy.h
* platform.[ch] - missing from cw1200 (mainly sunxi platform stuff that needs to be converted to use devicetree anyway)
* pm.[ch]
* queue.[ch]
* scan.[ch]
* sta.[ch]
* txrx.[ch]
* wsm.[ch]
* xr_version.h
