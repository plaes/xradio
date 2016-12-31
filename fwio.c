/*
 * Firmware I/O code for mac80211 ST-Ericsson CW1200 drivers
 *
 * Copyright (c) 2010, ST-Ericsson
 * Author: Dmitry Tarnyagin <dmitry.tarnyagin@lockless.no>
 * Copyright (c) 2013, XRadio
 *
 * Based on:
 * ST-Ericsson UMAC CW1200 driver which is
 * Copyright (c) 2010, ST-Ericsson
 * Author: Ajitpal Singh <ajitpal.singh@stericsson.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/firmware.h>

#include "cw1200.h"
#include "fwio.h"
#include "hwio.h"
#include "hwbus.h"
#include "bh.h"

static int cw1200_get_hw_type(u32 config_reg_val, int *major_revision)
{
	int hw_type = -1;
	u32 silicon_type = (config_reg_val >> 24) & 0x7;
	u32 silicon_vers = (config_reg_val >> 31) & 0x1;

	/* TODO: major_revision for Allwinner is 0x4, hw_type = 1 */
	pr_info("Silicon type: %d, version: %d.\n", silicon_type, silicon_vers);

	switch (silicon_type) {
	case 0x00:
		*major_revision = 1;
		hw_type = HIF_9000_SILICON_VERSATILE;
		break;
	case 0x01:
	case 0x02: /* CW1x00 */
	case 0x04: /* CW1x60 */
		*major_revision = silicon_type;
		if (silicon_vers)
			hw_type = HIF_8601_VERSATILE;
		else
			hw_type = HIF_8601_SILICON;
		break;
	default:
		break;
	}

	return hw_type;
}

/*
 * This function is called to Parse the SDD file
 * to extract some informations
 */
static int cw1200_parse_sdd(struct cw1200_common *priv, u32 *dpll)
{
	int ret = 0;
	const char *sdd_path = NULL;
	struct cw1200_sdd *pElement = NULL;
	int parsedLength = 0;

	sta_printk(XRADIO_DBG_TRC,"%s\n", __func__);
	SYS_BUG(priv->sdd != NULL);

	/* select and load sdd file depend on hardware version. */
	switch (priv->hw_revision) {
	case XR819_HW_REV0:
		sdd_path = XR819_SDD_FILE;
		break;
	default:
		cw1200_dbg(XRADIO_DBG_ERROR, "%s: unknown hardware version.\n", __func__);
		return ret;
	}

	ret = request_firmware(&priv->sdd, sdd_path, priv->pdev);
	if (unlikely(ret)) {
		cw1200_dbg(XRADIO_DBG_ERROR, "%s: can't load sdd file %s.\n",
		           __func__, sdd_path);
		return ret;
	}

	//parse SDD config.
	priv->is_BT_Present = false;
	pElement = (struct cw1200_sdd *)priv->sdd->data;
	parsedLength += (FIELD_OFFSET(struct cw1200_sdd, data) + pElement->length);
	pElement = FIND_NEXT_ELT(pElement);

	while (parsedLength < priv->sdd->size) {
		switch (pElement->id) {
		case SDD_PTA_CFG_ELT_ID:
			priv->conf_listen_interval = (*((u16 *)pElement->data+1) >> 7) & 0x1F;
			priv->is_BT_Present = true;
			cw1200_dbg(XRADIO_DBG_NIY, "PTA element found.Listen Interval %d\n",
			           priv->conf_listen_interval);
			break;
		case SDD_REFERENCE_FREQUENCY_ELT_ID:
			switch(*((uint16_t*)pElement->data)) {
			case 0x32C8:
				*dpll = 0x1D89D241;
				break;
			case 0x3E80:
				*dpll = 0x1E1;
				break;
			case 0x41A0:
				*dpll = 0x124931C1;
				break;
			case 0x4B00:
				*dpll = 0x191;
				break;
			case 0x5DC0:
				*dpll = 0x141;
				break;
			case 0x6590:
				*dpll = 0x0EC4F121;
				break;
			case 0x8340:
				*dpll = 0x92490E1;
				break;
			case 0x9600:
				*dpll = 0x100010C1;
				break;
			case 0x9C40:
				*dpll = 0xC1;
				break;
			case 0xBB80:
				*dpll = 0xA1;
				break;
			case 0xCB20:
				*dpll = 0x7627091;
				break;
			default:
				*dpll = DPLL_INIT_VAL_XRADIO;
				cw1200_dbg(XRADIO_DBG_WARN, "Unknown Reference clock frequency." 
				           "Use default DPLL value=0x%08x.", DPLL_INIT_VAL_XRADIO);
				break;
			}
		default:
			break;
		}
		parsedLength += (FIELD_OFFSET(struct cw1200_sdd, data) + pElement->length);
		pElement = FIND_NEXT_ELT(pElement);
	}
	
	cw1200_dbg(XRADIO_DBG_MSG, "sdd size=%d parse len=%d.\n", 
	           priv->sdd->size, parsedLength);

	//
	if (priv->is_BT_Present == false) {
		priv->conf_listen_interval = 0;
		cw1200_dbg(XRADIO_DBG_NIY, "PTA element NOT found.\n");
	}
	return ret;
}

#define CW1200_APB	APB_ADDR

static int cw1200_firmware(struct cw1200_common *priv)
{
	int ret, block, num_blocks;
	unsigned i;
	u32 val32;
	u32 put = 0, get = 0;
	u8 *buf = NULL;
	const char *fw_path;
	const struct firmware *firmware = NULL;

	/* Macroses are local. */
#define APB_WRITE(reg, val) \
	do { \
		ret = cw1200_apb_write_32(priv, CW1200_APB(reg), (val)); \
		if (ret < 0) \
			goto exit; \
	} while (0)
#define APB_WRITE2(reg, val) \
	do { \
		ret = cw1200_apb_write_32(priv, CW1200_APB(reg), (val)); \
		if (ret < 0) \
			goto free_buffer; \
	} while (0)
#define APB_READ(reg, val) \
	do { \
		ret = cw1200_apb_read_32(priv, CW1200_APB(reg), &(val)); \
		if (ret < 0) \
			goto free_buffer; \
	} while (0)
#define REG_WRITE(reg, val) \
	do { \
		ret = cw1200_reg_write_32(priv, (reg), (val)); \
		if (ret < 0) \
			goto exit; \
	} while (0)
#define REG_READ(reg, val) \
	do { \
		ret = cw1200_reg_read_32(priv, (reg), &(val)); \
		if (ret < 0) \
			goto exit; \
	} while (0)

	switch (priv->hw_revision) {
	case XR819_HW_REV0:
		fw_path = XR819_FIRMWARE;
		break;
	default:
		pr_err("Invalid silicon revision %d.\n", priv->hw_revision);
		return -EINVAL;
	}

	/* Initialize common registers */
	APB_WRITE(DOWNLOAD_IMAGE_SIZE_REG, DOWNLOAD_ARE_YOU_HERE);
	APB_WRITE(DOWNLOAD_PUT_REG, 0);
	APB_WRITE(DOWNLOAD_GET_REG, 0);
	APB_WRITE(DOWNLOAD_STATUS_REG, DOWNLOAD_PENDING);
	APB_WRITE(DOWNLOAD_FLAGS_REG, 0);

	/* Release CPU from RESET */
	REG_READ(HIF_CONFIG_REG_ID, val32);
	val32 &= ~HIF_CONFIG_CPU_RESET_BIT;
	REG_WRITE(HIF_CONFIG_REG_ID, val32);

	/* Enable Clock */
	val32 &= ~HIF_CONFIG_CPU_CLK_DIS_BIT;
	REG_WRITE(HIF_CONFIG_REG_ID, val32);

	/* Load a firmware file */
	ret = request_firmware(&firmware, fw_path, priv->pdev);
	if (ret) {
		pr_err("Can't load firmware file %s.\n", fw_path);
		goto exit;
	}

	buf = kmalloc(DOWNLOAD_BLOCK_SIZE, GFP_KERNEL | GFP_DMA);
	if (!buf) {
		pr_err("Can't allocate firmware load buffer.\n");
		ret = -ENOMEM;
		goto firmware_release;
	}

	/* Check if the bootloader is ready */
	for (i = 0; i < 100; i += 1 + i / 2) {
		APB_READ(DOWNLOAD_IMAGE_SIZE_REG, val32);
		if (val32 == DOWNLOAD_I_AM_HERE)
			break;
		mdelay(i);
	} /* End of for loop */

	if (val32 != DOWNLOAD_I_AM_HERE) {
		pr_err("Bootloader is not ready.\n");
		ret = -ETIMEDOUT;
		goto free_buffer;
	}

	/* Calculcate number of download blocks */
	num_blocks = (firmware->size - 1) / DOWNLOAD_BLOCK_SIZE + 1;

	/* Updating the length in Download Ctrl Area */
	val32 = firmware->size; /* Explicit cast from size_t to u32 */
	APB_WRITE2(DOWNLOAD_IMAGE_SIZE_REG, val32);

	/* Firmware downloading loop */
	for (block = 0; block < num_blocks; block++) {
		size_t tx_size;
		size_t block_size;

		/* check the download status */
		APB_READ(DOWNLOAD_STATUS_REG, val32);
		if (val32 != DOWNLOAD_PENDING) {
			pr_err("Bootloader reported error %d.\n", val32);
			ret = -EIO;
			goto free_buffer;
		}

		/* loop until put - get <= 24K */
		for (i = 0; i < 100; i++) {
			APB_READ(DOWNLOAD_GET_REG, get);
			if ((put - get) <=
			    (DOWNLOAD_FIFO_SIZE - DOWNLOAD_BLOCK_SIZE))
				break;
			mdelay(i);
		}

		if ((put - get) > (DOWNLOAD_FIFO_SIZE - DOWNLOAD_BLOCK_SIZE)) {
			pr_err("Timeout waiting for FIFO.\n");
			ret = -ETIMEDOUT;
			goto free_buffer;
		}

		/* calculate the block size */
		tx_size = block_size = min_t(size_t, firmware->size - put,
					DOWNLOAD_BLOCK_SIZE);

		memcpy(buf, &firmware->data[put], block_size);
		if (block_size < DOWNLOAD_BLOCK_SIZE) {
			memset(&buf[block_size], 0,
			       DOWNLOAD_BLOCK_SIZE - block_size);
			tx_size = DOWNLOAD_BLOCK_SIZE;
		}

		/* send the block to sram */
		ret = cw1200_apb_write(priv,
			CW1200_APB(DOWNLOAD_FIFO_OFFSET +
				   (put & (DOWNLOAD_FIFO_SIZE - 1))),
			buf, tx_size);
		if (ret < 0) {
			pr_err("Can't write firmware block @ %d!\n",
			       put & (DOWNLOAD_FIFO_SIZE - 1));
			goto free_buffer;
		}

		/* update the put register */
		put += block_size;
		APB_WRITE2(DOWNLOAD_PUT_REG, put);
	} /* End of firmware download loop */

	/* Wait for the download completion */
	for (i = 0; i < 300; i += 1 + i / 2) {
		APB_READ(DOWNLOAD_STATUS_REG, val32);
		if (val32 != DOWNLOAD_PENDING)
			break;
		mdelay(i);
	}
	if (val32 != DOWNLOAD_SUCCESS) {
		pr_err("Wait for download completion failed: 0x%.8X\n", val32);
		ret = -ETIMEDOUT;
		goto free_buffer;
	} else {
		pr_info("Firmware download completed.\n");
		ret = 0;
	}

free_buffer:
	kfree(buf);
firmware_release:
	release_firmware(firmware);
exit:
	return ret;

#undef APB_WRITE
#undef APB_WRITE2
#undef APB_READ
#undef REG_WRITE
#undef REG_READ
}


static int config_reg_read(struct cw1200_common *priv, u32 *val)
{
	/* TODO: Support Allwinner xr819 */
	switch (priv->hw_type) {
	case HIF_9000_SILICON_VERSATILE: {
		u16 val16;
		int ret = cw1200_reg_read_16(priv,
					     ST90TDS_CONFIG_REG_ID,
					     &val16);
		if (ret < 0)
			return ret;
		*val = val16;
		return 0;
	}
	case HIF_8601_VERSATILE:
	case HIF_8601_SILICON:
	default:
		cw1200_reg_read_32(priv, ST90TDS_CONFIG_REG_ID, val);
		break;
	}
	return 0;
}

static int config_reg_write(struct cw1200_common *priv, u32 val)
{
	/* TODO: Support Allwinner xr819 */
	switch (priv->hw_type) {
	case HIF_9000_SILICON_VERSATILE:
		return cw1200_reg_write_16(priv,
					   ST90TDS_CONFIG_REG_ID,
					   (u16)val);
	case HIF_8601_VERSATILE:
	case HIF_8601_SILICON:
	default:
		return cw1200_reg_write_32(priv, ST90TDS_CONFIG_REG_ID, val);
	}
	return 0;
}

static int cw1200_bootloader(struct cw1200_common *priv)
{
	int ret = -1;
	u32 i = 0;
	const char *bl_path = XR819_BOOTLOADER;
	u32  addr = AHB_MEMORY_ADDRESS;
	u32 *data = NULL;
	const struct firmware *bootloader = NULL;
	cw1200_dbg(XRADIO_DBG_TRC,"%s\n", __FUNCTION__);

	/* Load a bootloader file */
	ret = request_firmware(&bootloader, bl_path, priv->pdev);
	if (ret) {
		cw1200_dbg(XRADIO_DBG_ERROR, "%s: can't load bootloader file %s.\n",
		           __func__, bl_path);
		goto error;
	}

	cw1200_dbg(XRADIO_DBG_NIY, "%s: bootloader size = %d, loopcount = %d\n",
	          __func__,bootloader->size, (bootloader->size)/4);

	/* Down bootloader. */
	data = (u32 *)bootloader->data;
	for(i = 0; i < (bootloader->size)/4; i++) {
		REG_WRITE(HIF_SRAM_BASE_ADDR_REG_ID, addr);
		REG_WRITE(HIF_AHB_DPORT_REG_ID,data[i]);
		if(i == 100 || i == 200 || i == 300 || i == 400 || i == 500 || i == 600 )
			cw1200_dbg(XRADIO_DBG_NIY, "%s: addr = 0x%x,data = 0x%x\n",__func__,addr, data[i]);
		addr += 4;
	}
	cw1200_dbg(XRADIO_DBG_ALWY, "Bootloader complete\n");

error:
	if(bootloader) {
		release_firmware(bootloader);
	}
	return ret;  
}

int cw1200_load_firmware(struct cw1200_common *priv)
{
	int ret;
	int i;
	u32 val32;
	u16 val16;
	int major_revision = -1;

	u32 dpll = 0;

	/* Read CONFIG Register */
	ret = cw1200_reg_read_32(priv, HIF_CONFIG_REG_ID, &val32);
	if (ret < 0) {
		pr_err("Can't read config register.\n");
		return ret;
	}

	if (val32 == 0 || val32 == 0xffffffff) {
		pr_err("Bad config register value (0x%08x)\n", val32);
		ret = -EIO;
		goto out;
	}

	priv->hw_type = cw1200_get_hw_type(val32, &major_revision);
	if (priv->hw_type < 0) {
		pr_err("Can't deduce hardware type.\n");
		ret = -ENOTSUPP;
		return ret;
	}

	switch (priv->hw_type) {
	case HIF_HW_TYPE_XRADIO:
		cw1200_dbg(XRADIO_DBG_NIY, "%s: HW_TYPE_XRADIO detected.\n", __func__);
		break;
	default:
		cw1200_dbg(XRADIO_DBG_ERROR, "%s: Unknown hardware: %d.\n",  
		           __func__, priv->hw_type);
		return -ENOTSUPP;
	}
	if (major_revision == 4) {
		priv->hw_revision = XR819_HW_REV0;
		cw1200_dbg(XRADIO_DBG_ALWY, "XRADIO_HW_REV 1.0 detected.\n");
	} else {
		cw1200_dbg(XRADIO_DBG_ERROR, "%s: Unsupported major revision %d.\n",
		           __func__, major_revision);
		return -ENOTSUPP;
	}
	
	//load sdd file, and get config from it.
	ret = cw1200_parse_sdd(priv, &dpll);
	if (ret < 0) {
		return ret;
	}

	/* Set DPLL Reg value, and read back to confirm writes work */
	ret = cw1200_reg_write_32(priv, HIF_TSET_GEN_R_W_REG_ID, dpll);
	if (ret < 0) {
		pr_err("Can't write DPLL register.\n");
		goto out;
	}

	msleep(5);

	ret = cw1200_reg_read_32(priv,
		HIF_TSET_GEN_R_W_REG_ID, &val32);
	if (ret < 0) {
		pr_err("Can't read DPLL register.\n");
		goto out;
	}

	if (val32 != dpll) {
		pr_err("Unable to initialise DPLL register. Wrote 0x%.8X, Read 0x%.8X.\n",
		       dpll, val32);
		ret = -EIO;
		goto out;
	}

	/* Set wakeup bit in device */
	ret = cw1200_reg_read_16(priv, HIF_CONTROL_REG_ID, &val16);
	if (ret < 0) {
		pr_err("set_wakeup: can't read control register.\n");
		goto out;
	}

	ret = cw1200_reg_write_16(priv, HIF_CONTROL_REG_ID,
		val16 | HIF_CTRL_WUP_BIT);
	if (ret < 0) {
		pr_err("set_wakeup: can't write control register.\n");
		goto out;
	}

	/* Wait for wakeup */
	for (i = 0; i < 300; i += (1 + i / 2)) {
		ret = cw1200_reg_read_16(priv,
			HIF_CONTROL_REG_ID, &val16);
		if (ret < 0) {
			pr_err("wait_for_wakeup: can't read control register.\n");
			goto out;
		}

		if (val16 & HIF_CTRL_RDY_BIT)
			break;

		msleep(i);
	}

	if ((val16 & HIF_CTRL_RDY_BIT) == 0) {
		pr_err("wait_for_wakeup: device is not responding.\n");
		ret = -ETIMEDOUT;
		goto out;
	}

	/* Checking for access mode and download firmware. */
	ret = cw1200_reg_read_32(priv, HIF_CONFIG_REG_ID, &val32);
	if (ret < 0) {
		cw1200_dbg(XRADIO_DBG_ERROR, "%s: check_access_mode: "
		           "can't read config register.\n", __func__);
		goto out;
	}
	if (val32 & HIF_CONFIG_ACCESS_MODE_BIT) {
		/* Down bootloader. */
		ret = cw1200_bootloader(priv);
		if (ret < 0) {
			cw1200_dbg(XRADIO_DBG_ERROR, "%s: can't download bootloader.\n", __func__);
			goto out;
		}
		/* Down firmware. */
		ret = cw1200_firmware(priv);
		if (ret < 0) {
			cw1200_dbg(XRADIO_DBG_ERROR, "%s: can't download firmware.\n", __func__);
			goto out;
		}
	} else {
		cw1200_dbg(XRADIO_DBG_WARN, "%s: check_access_mode: "
		           "device is already in QUEUE mode.\n", __func__);
		/* TODO: verify this branch. Do we need something to do? */
	}

	/* Register Interrupt Handler */
	ret = priv->hwbus_ops->irq_subscribe(priv->hwbus_priv, 
	                                      (hwbus_irq_handler)cw1200_irq_handler, 
	                                       priv);
	if (ret < 0) {
		cw1200_dbg(XRADIO_DBG_ERROR, "%s: can't register IRQ handler.\n", __func__);
		goto out;
	}

	if (HIF_HW_TYPE_XRADIO  == priv->hw_type) {
		/* If device is XRADIO the IRQ enable/disable bits
		 * are in CONFIG register */
		ret = cw1200_reg_read_32(priv, HIF_CONFIG_REG_ID, &val32);
		if (ret < 0) {
			cw1200_dbg(XRADIO_DBG_ERROR, "%s: enable_irq: can't read " \
			           "config register.\n", __func__);
			goto unsubscribe;
		}
		ret = cw1200_reg_write_32(priv, HIF_CONFIG_REG_ID,
			val32 | HIF_CONF_IRQ_RDY_ENABLE);
		if (ret < 0) {
			cw1200_dbg(XRADIO_DBG_ERROR, "%s: enable_irq: can't write " \
			           "config register.\n", __func__);
			goto unsubscribe;
		}
	} else {
		/* If device is XRADIO the IRQ enable/disable bits
		 * are in CONTROL register */
		/* Enable device interrupts - Both DATA_RDY and WLAN_RDY */
		ret = cw1200_reg_read_16(priv, HIF_CONFIG_REG_ID, &val16);
		if (ret < 0) {
			cw1200_dbg(XRADIO_DBG_ERROR, "%s: enable_irq: can't read " \
			           "control register.\n", __func__);
			goto unsubscribe;
		}
		ret = cw1200_reg_write_16(priv, HIF_CONFIG_REG_ID, 
		                          val16 | HIF_CTRL_IRQ_RDY_ENABLE);
		if (ret < 0) {
			cw1200_dbg(XRADIO_DBG_ERROR, "%s: enable_irq: can't write " \
			           "control register.\n", __func__);
			goto unsubscribe;
		}

	}

	/* Configure device for MESSSAGE MODE */
	ret = cw1200_reg_read_32(priv, HIF_CONFIG_REG_ID, &val32);
	if (ret < 0) {
		pr_err("Can't read config register.\n");
		goto unsubscribe;
	}
	ret = cw1200_reg_write_32(priv, HIF_CONFIG_REG_ID,
	                          val32 & ~HIF_CONFIG_ACCESS_MODE_BIT);
	if (ret < 0) {
		pr_err("Can't write config register.\n");
		goto unsubscribe;
	}

	/* Unless we read the CONFIG Register we are
	 * not able to get an interrupt
	 */
	mdelay(10);
	cw1200_reg_read_32(priv, HIF_CONFIG_REG_ID, &val32);
	return 0;

unsubscribe:
	priv->hwbus_ops->irq_unsubscribe(priv->hwbus_priv);
out:
	if (priv->sdd) {
		release_firmware(priv->sdd);
		priv->sdd = NULL;
	}
	return ret;
}

int cw1200_dev_deinit(struct cw1200_common *priv)
{
	priv->hwbus_ops->irq_unsubscribe(priv->hwbus_priv);
	if (priv->sdd) {
		release_firmware(priv->sdd);
		priv->sdd = NULL;
	}
	return 0;
}
