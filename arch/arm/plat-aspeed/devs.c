/********************************************************************************
* File Name     : linux/arch/arm/plat-aspeed/devs.c
* Author        : Ryan chen
*
* Copyright (C) 2012-2020  ASPEED Technology Inc.
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by the Free Software Foundation;
* either version 2 of the License, or (at your option) any later version.
* 
* This program is distributed in the hope that it will be useful,  but WITHOUT ANY WARRANTY;
* without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

* History      :
*    1. 2012/08/10 create this file [Ryan Chen]
*
********************************************************************************/

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/platform_device.h>

#include <mach/platform.h>

#include <plat/devs.h>

typedef void (init_fnc_t) (void);

init_fnc_t __initdata *init_all_device[] = {
	ast_add_device_lpc,
	ast_add_device_uart,
	ast_add_device_vuart,	
	ast_add_device_watchdog,
	ast_add_device_rtc,	
	ast_add_device_i2c,
	ast_add_device_spi,
//ast_add_device_ehci, disabled by tfang for USB HUB mode
	ast_add_device_nand,
	ast_add_device_flash,
	ast_add_device_pwm_fan,
	ast_add_device_adc,
	ast_add_device_gpio,		
	ast_add_device_sgpio,			
	ast_add_device_peci,	
	ast_add_device_fb,
//	ast_add_device_sdhci, disabled by tfang
//	ast_add_device_uhci, disabled by tfang
//	ast_add_device_video, disabled by tfang
	ast_add_device_kcs,
	ast_add_device_mailbox,
	ast_add_device_snoop,
	ast_add_device_gmac,
	ast_add_device_virthub,
//	ast_add_device_nand,
	NULL,
};

void __init ast_add_all_devices(void)
{
	init_fnc_t **init_fnc_ptr;

	for (init_fnc_ptr = init_all_device; *init_fnc_ptr; ++init_fnc_ptr) {
		(*init_fnc_ptr)();
	}

	return;
}
