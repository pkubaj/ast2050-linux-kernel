/* arch/arm/mach-aspeed/include/mach/regs-ast2300-scu.h
 *
 * Copyright (C) 2012-2020  ASPEED Technology Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *   History      : 
 *    1. 2012/12/29 Ryan Chen Create
 * 
********************************************************************************/
#ifndef __AST_SCU_H
#define __AST_SCU_H                     1

/*
 *  Register for SCU
 *  */
#define AST_SCU_PROTECT		0x00		/*	protection key register	*/
#define AST_SCU_RESET		0x04		/*	system reset control register */
#define AST_SCU_CLK_SEL		0x08		/*	clock selection register	*/
#define AST_SCU_CLK_STOP	0x0C		/*	clock stop control register	*/
#define AST_SCU_COUNT_CTRL	0x10		/*	frequency counter control register	*/
#define AST_SCU_COUNT_VAL	0x14		/*	frequency counter measure register 	*/
#define AST_SCU_INTR_CTRL	0x18		/*	Interrupt control and status register	*/
#define AST_SCU_D2_PLL		0x1C		/*	D2-PLL Parameter  register	*/
#define AST_SCU_M_PLL		0x20		/*	M-PLL Parameter register		*/
#define AST_SCU_H_PLL		0x24		/*	H-PLL Parameter register		*/
#define AST_SCU_FREQ_LIMIT	0x28		/*	frequency counter comparsion register */
#define AST_SCU_MISC1_CTRL	0x2C		/*	Misc. Control register */
#define AST_SCU_PCI_CONF1	0x30		/*	PCI configuration setting register#1 */
#define AST_SCU_PCI_CONF2	0x34		/*	PCI configuration setting register#2 */
#define AST_SCU_PCI_CONF3	0x38		/*	PCI configuration setting register#3 */
#define AST_SCU_SYS_CTRL	0x3C		/*	System reset contrl/status register*/
#define AST_SCU_SOC_SCRATCH0	0x40		/*	SOC scratch 0~31 register */
#define AST_SCU_SOC_SCRATCH1	0x44		/*	SOC scratch 32~63 register */
#define AST_SCU_VGA0		0x40		/*	VGA fuction handshake register */
#define AST_SCU_VGA1		0x44		/*	VGA fuction handshake register */
#define AST_SCU_MAC_CLK		0x48		/*	MAC interface clock delay setting register */
#define AST_SCU_MISC2_CTRL	0x4C		/*	Misc. 2 Control register */
#define AST_SCU_VGA_SCRATCH0	0x50		/*	VGA Scratch register */
#define AST_SCU_VGA_SCRATCH1	0x54		/*	VGA Scratch register */
#define AST_SCU_VGA_SCRATCH2	0x58		/*	VGA Scratch register */
#define AST_SCU_VGA_SCRATCH3	0x5c		/*	VGA Scratch register */
#define AST_SCU_VGA_SCRATCH4	0x60		/*	VGA Scratch register */
#define AST_SCU_VGA_SCRATCH5	0x64		/*	VGA Scratch register */
#define AST_SCU_VGA_SCRATCH6	0x68		/*	VGA Scratch register */
#define AST_SCU_VGA_SCRATCH7	0x6c		/*	VGA Scratch register */
#define AST_SCU_HW_STRAP1			0x70		/*	hardware strapping register */
#if defined(CONFIG_ARCH_2300) || defined(CONFIG_ARCH_2400)
#define AST_SCU_RAMDOM_GEN		0x74		/*	random number generator register */
#endif
#if defined(CONFIG_ARCH_1100) || defined(CONFIG_ARCH_2200)
#define AST_SCU_MULTI_FUNC_2	0x78
#else
#define AST_SCU_RAMDOM_DATA		0x78		/*	random number generator data output*/
#endif
#define AST_SCU_REVISION_ID		0x7C		/*	Silicon revision ID register */
#if defined(CONFIG_ARCH_2300) || defined(CONFIG_ARCH_2400)
#define AST_SCU_FUN_PIN_CTRL1		0x80		/*	Multi-function Pin Control#1*/
#define AST_SCU_FUN_PIN_CTRL2		0x84		/*	Multi-function Pin Control#2*/
#define AST_SCU_FUN_PIN_CTRL3		0x88		/*	Multi-function Pin Control#3*/
#define AST_SCU_FUN_PIN_CTRL4		0x8C		/*	Multi-function Pin Control#4*/
#define AST_SCU_FUN_PIN_CTRL5		0x90		/*	Multi-function Pin Control#5*/
#define AST_SCU_FUN_PIN_CTRL6		0x94		/*	Multi-function Pin Control#6*/
#else
#define AST_SCU_FUN_PIN_CTRL1		0x74		/*	Multi-function Pin Control#1*/
#define AST_SCU_FUN_PIN_CTRL2		0x78		/*	Multi-function Pin Control#2*/
#endif
#define AST_SCU_WDT_RESET		0x9C		/*	Watchdog Reset Selection */
#define AST_SCU_FUN_PIN_CTRL7		0xA0		/*	Multi-function Pin Control#7*/
#define AST_SCU_FUN_PIN_CTRL8		0xA4		/*	Multi-function Pin Control#8*/
#define AST_SCU_FUN_PIN_CTRL9		0xA8		/*	Multi-function Pin Control#9*/
#define AST_SCU_PWR_SAVING_EN		0xC0		/*	Power Saving Wakeup Enable*/
#define AST_SCU_PWR_SAVING_CTRL		0xC4		/*	Power Saving Wakeup Control*/
#define AST_SCU_HW_STRAP2			0xD0		/*	Haardware strapping register set 2*/
#define AST_SCU_COUNTER4			0xE0		/*	SCU Free Run Counter Read Back #4*/
#define AST_SCU_COUNTER4_EXT		0xE4		/*	SCU Free Run Counter Extended Read Back #4*/

//CPU 2 
#define AST_SCU_CPU2_CTRL			0x100		/*	CPU2 Control Register*/
#define AST_SCU_CPU2_BASE0_ADDR		0x104		/*	CPU2 Base Address for Segment 0x00:0000~0x1F:FFFF*/
#define AST_SCU_CPU2_BASE1_ADDR		0x108		/*	CPU2 Base Address for Segment 0x20:0000~0x3F:FFFF*/
#define AST_SCU_CPU2_BASE2_ADDR		0x10C		/*	CPU2 Base Address for Segment 0x40:0000~0x5F:FFFF*/
#define AST_SCU_CPU2_BASE3_ADDR		0x110		/*	CPU2 Base Address for Segment 0x60:0000~0x7F:FFFF*/
#define AST_SCU_CPU2_BASE4_ADDR		0x114		/*	CPU2 Base Address for Segment 0x80:0000~0xFF:FFFF*/
#define AST_SCU_CPU2_CACHE_CTRL		0x118		/*	CPU2 Cache Function Control */

//
#define AST_SCU_UART24_REF			0x160		/*	Generate UART 24Mhz Ref from H-PLL when CLKIN is 25Mhz */
#define AST_SCU_PCIE_CONFIG_SET		0x180		/*	PCI-E Configuration Setting Control Register */
#define AST_SCU_BMC_MMIO_DEC		0x184		/*	BMC MMIO Decode Setting Register */
#define AST_SCU_DEC_AREA1			0x188		/*	1st relocated controller decode area location */
#define AST_SCU_DEC_AREA2			0x18C		/*	2nd relocated controller decode area location */
#define AST_SCU_MBOX_DEC_AREA		0x190		/*	Mailbox decode area location*/
#define AST_SCU_SRAM_DEC_AREA0		0x194		/*	Shared SRAM area decode location*/
#define AST_SCU_SRAM_DEC_AREA1		0x198		/*	Shared SRAM area decode location*/
#define AST_SCU_BMC_CLASS			0x19C		/*	BMC device class code and revision ID */
#define AST_SCU_BMC_DEV_ID			0x1A4		/*	BMC device ID */


/*	AST_SCU_PROTECT: 0x00  - protection key register */
#define SCU_PROTECT_UNLOCK			0x1688A8A8

/*	AST_SCU_RESET :0x04	 - system reset control register */
#if defined (CONFIG_ARCH_AST1010)
#define SCU_RESET_ADC				(0x1 << 6)
#define SCU_RESET_JTAG				(0x1 << 5)
#define SCU_RESET_MAC0				(0x1 << 4)
#define SCU_RESET_PECI				(0x1 << 3)
#define SCU_RESET_PWM				(0x1 << 2)
#define SCU_RESET_LPC				(0x1 << 1)
#define SCU_RESET_I2C				(0x1)
#else
#define SCU_RESET_X_DMA				(0x1 << 25)
#define SCU_RESET_MCTP				(0x1 << 24)
#define SCU_RESET_ADC				(0x1 << 23)
#define SCU_RESET_JTAG				(0x1 << 22)
#define SCU_PWAKE_PIN_EN			(0x1 << 20)
#define SCU_PWAKE_PIN_OUT			(0x1 << 19)
#define SCU_RESET_MIC				(0x1 << 18)
#define SCU_RESET_RESV				(0x1 << 17) //must keep 1 
#define SCU_RESET_SD				(0x1 << 16)
#define SCU_RESET_USB11				(0x1 << 15)
#define SCU_RESET_USB20				(0x1 << 14)
#define SCU_RESET_CRT				(0x1 << 13)
#define SCU_RESET_MAC1				(0x1 << 12)
#define SCU_RESET_MAC0				(0x1 << 11)
#define SCU_RESET_PECI				(0x1 << 10)
#define SCU_RESET_PWM				(0x1 << 9)
#define SCU_PCI_VGA_DIS				(0x1 << 8)
#define SCU_RESET_2D				(0x1 << 7)
#define SCU_RESET_VIDEO				(0x1 << 6)
#define SCU_RESET_LPC				(0x1 << 5)
#define SCU_RESET_HAC				(0x1 << 4)
#define SCU_RESET_USB11_HID			(0x1 << 3)
#define SCU_RESET_I2C				(0x1 << 2)
#define SCU_RESET_AHB				(0x1 << 1)
#define SCU_RESET_SRAM_CTRL			(0x1 << 0)
#endif

/*	AST_SCU_CLK_SEL	 : 0x08 - clock selection register	*/
#if defined(CONFIG_ARCH_AST1010)
#define SCU_CLK_MAC_DIV(x)			(x << 12)
#define SCU_CLK_MAC_MASK			(0x3 << 12)
#define SCU_LHCLK_SOURCE_EN			(0x1 << 11)		//0: ext , 1:internel
#define SCU_LHCLK_LPC_DIV(x)		(x << 8)
#define SCU_LHCLK_LPC_MASK			(0x7 << 8)
#define SCU_PCLK_APB_DIV(x)			(x << 5)
#define SCU_GET_PCLK_DIV(x)			((x >> 5) & 0x7)
#define SCU_PCLK_APB_DIV_MASK		(0x7 << 5)		//limitation on PCLK .. PCLK > 0.5*LCLK (33Mhz)
#define SCU_CLK_CPU_AHB_SLOW_EN		(0x1 << 4)
#define SCU_CLK_CPU_AHB_SLOW(x)		(x << 3)
#define SCU_CLK_CPU_AHB_SLOW_MASK	(0x3 << 3)
#define SCU_GET_AHB_DIV(x)			((x >> 3) & 0x3)
#define SCU_CLK_CPU_AHB_SLOW_IDLE	(0x1 << 1)
#define SCU_CLK_CPU_AHB_DYN_SLOW_EN	(0x1)
#else
#define SCU_CLK_VIDEO_SLOW_EN		(0x1 << 31)
#define SCU_CLK_VIDEO_SLOW_SET(x)	(x << 28)
#define SCU_CLK_VIDEO_SLOW_MASK		(0x7 << 28)
#define SCU_CLK_2D_ENG_GCLK_INVERT	(0x1 << 27)		//valid only at CRT mode SCU2C[7]
#define SCU_CLK_2D_ENG_THROT_EN		(0x1 << 26)		//valid only at CRT mode SCU2C[7]
#define SCU_PCLK_APB_DIV(x)			(x << 23)
#define SCU_GET_PCLK_DIV(x)			((x >> 23) & 0x7)
#define SCU_PCLK_APB_DIV_MASK		(0x7 << 23)		//limitation on PCLK .. PCLK > 0.5*LCLK (33Mhz)
#define SCU_GET_LHCLK_DIV(x)		((x >> 20) & 0x7)
#define SCU_SET_LHCLK_DIV(x)		(x << 20)
#define SCU_LHCLK_DIV_MASK			(0x7 << 20)
#define SCU_LHCLK_SOURCE_EN			(0x1 << 19)		//0: ext , 1:internel
#define SCU_CLK_MAC_DIV(x)			(x << 16)
#define SCU_CLK_MAC_MASK			(0x7 << 16)
#define SCU_CLK_SD_EN				(0x1 << 15)
#define SCU_CLK_SD_DIV(x)			(x << 12)
#define SCU_CLK_SD_GET_DIV(x)		((x >> 12) & 0x7)
#define SCU_CLK_SD_MASK				(0x7 << 12)
#define SCU_CLK_VIDEO_DELAY(x)		(x << 8)
#define SCU_CLK_VIDEO_DELAY_MASK	(0xf << 8)
#define SCU_CLK_CPU_AHB_SLOW_EN		(0x1 << 7)
#define SCU_CLK_CPU_AHB_SLOW(x)		(x << 4)
#define SCU_CLK_CPU_AHB_SLOW_MASK	(0x7 << 4)
#define SCU_GET_AHB_DIV(x)			((x >> 4) & 0x7)
#define SCU_ECLK_SOURCE(x)			(x << 2)
#define SCU_ECLK_SOURCE_MASK		(0x3 << 2)
#define SCU_CLK_CPU_AHB_SLOW_IDLE	(0x1 << 1)
#define SCU_CLK_CPU_AHB_DYN_SLOW_EN	(0x1 << 0)

#endif

/*	AST_SCU_CLK_STOP : 0x0C - clock stop control register	*/
#if defined(CONFIG_ARCH_AST1010)
#define SCU_LHCLK_STOP_EN			(0x1 << 7)
#define SCU_MAC0CLK_STOP_EN			(0x1 << 6)
#define SCU_UART3_CLK_STOP_EN		(0x1 << 5)
#define SCU_UART2_CLK_STOP_EN		(0x1 << 4)
#define SCU_UART1_CLK_STOP_EN		(0x1 << 3)
#define SCU_LCLK_STOP_EN			(0x1 << 2)
#define SCU_REFCLK_STOP_EN			(0x1 << 1)
#define SCU_MCLK_STOP_EN			(0x1)
#else
#define SCU_LHCLK_STOP_EN			(0x1 << 28)
#define SCU_SDCLK_STOP_EN			(0x1 << 27)
#define SCU_UART4CLK_STOP_EN		(0x1 << 26)
#define SCU_UART3CLK_STOP_EN		(0x1 << 25)
#define SCU_RSACLK_STOP_EN			(0x1 << 24)
//bit 22~23 must keep 1 
#define SCU_MAC1CLK_STOP_EN			(0x1 << 21)
#define SCU_MAC0CLK_STOP_EN			(0x1 << 20)
//bit 18~19 must keep 1 
#define SCU_UART5_CLK_STOP_EN		(0x1 << 17)
#define SCU_UART2_CLK_STOP_EN		(0x1 << 16)
#define SCU_UART1_CLK_STOP_EN		(0x1 << 15)
#define SCU_USB20_CLK_EN			(0x1 << 14)
#define SCU_YCLK_STOP_EN			(0x1 << 13)
#define SCU_D2CLK_STOP_EN			(0x1 << 10)
#define SCU_USB11CLK_STOP_EN		(0x1 << 9)
#define SCU_LCLK_STOP_EN			(0x1 << 8)
#define SCU_UCLK_STOP_EN			(0x1 << 7)
#define SCU_REFCLK_STOP_EN			(0x1 << 6)
#define SCU_DCLK_STOP_EN			(0x1 << 5)
#define SCU_SACLK_STOP_EN			(0x1 << 4)
#define SCU_VCLK_STOP_EN			(0x1 << 3)
#define SCU_MCLK_STOP_EN			(0x1 << 2)
#define SCU_GCLK_STOP_EN			(0x1 << 1)
#define SCU_ECLK_STOP_EN			(0x1 << 0)
#endif

/* AST_SCU_COUNT_CTRL : 0x10 - frequency counter control register	*/
#define SCU_FREQ_COMP_RESULT			(0x1 << 7) 
#define SCU_FREQ_MEASU_FINISH			(0x1 << 6)
#define SCU_FREQ_SOURCE_FOR_MEASU(x)	(x << 2)
#define SCU_FREQ_SOURCE_FOR_MEASU_MASK	(0xf << 2)

#define SCU_SOURCE_6M					0xf
#define SCU_SOURCE_12M					0xe
#define SCU_SOURCE_I2SM_CLK				0xd
#define SCU_SOURCE_H_CLK				0xc
#define SCU_SOURCE_B_CLK				0xb
#define SCU_SOURCE_D2_PLL				0xa

#define SCU_SOURCE_VIDEO_CLK			0x7
#define SCU_SOURCE_LPC_CLK				0x6
#define SCU_SOURCE_I2S_CLK				0x5
#define SCU_SOURCE_M_CLK				0x4
#define SCU_SOURCE_SALI_CLK				0x3
#define SCU_SOURCE_D_PLL				0x2
#define SCU_SOURCE_NAND					0x1
#define SCU_SOURCE_DEL_CELL				0x0

#define SCU_OSC_COUNT_EN				(0x1 << 1)
#define SCU_RING_OSC_EN					(0x1 << 0)


/*  AST_SCU_INTR_CTRL : 0x18 - Interrupt control and status register   */
#define INTR_LPC_H_L_RESET				(0x1 << 21)
#define INTR_LPC_L_H_RESET				(0x1 << 20)
#define INTR_PCIE_H_L_RESET				(0x1 << 19)
#define INTR_PCIE_L_H_RESET				(0x1 << 18)
#define INTR_VGA_SCRATCH_CHANGE			(0x1 << 17)
#define INTR_VGA_CURSOR_CHANGE			(0x1 << 16)
#define INTR_MSI_EN						(0x1 << 6)
#define INTR_LPC_H_L_RESET_EN			(0x1 << 5)
#define INTR_LPC_L_H_RESET_EN			(0x1 << 4)
#define INTR_PCIE_H_L_RESET_EN			(0x1 << 3)
#define INTR_PCIE_L_H_RESET_EN			(0x1 << 2)
#define INTR_VGA_SCRATCH_CHANGE_EN		(0x1 << 1)
#define INTR_VGA_CURSOR_CHANGE_EN		(0x1 << 0)

/*	AST_SCU_D2_PLL: 0x1C - D2-PLL Parameter  register */
#define SCU_D2_PLL_SET_PD2(x)			(x << 19)
#define SCU_D2_PLL_GET_PD2(x)			((x >> 19)&0x7)
#define SCU_D2_PLL_PD2_MASK				(0x7 << 19)
#define SCU_D2_PLL_BYPASS_EN			(0x1 << 18)
#define SCU_D2_PLL_OFF					(0x1 << 17)
#define SCU_D2_PLL_SET_PD(x)			(x << 15)
#define SCU_D2_PLL_GET_PD(x)			((x >> 15) &0x3)
#define SCU_D2_PLL_PD_MASK				(0x3 << 15)
#define SCU_D2_PLL_SET_OD(x)			(x << 13)
#define SCU_D2_PLL_GET_OD(x)			((x >> 13) & 0x3)
#define SCU_D2_PLL_OD_MASK				(0x3 << 13)
#define SCU_D2_PLL_SET_DENUM(x)			(x << 8)
#define SCU_D2_PLL_GET_DENUM(x)			((x >>8)&0x1f)
#define SCU_D2_PLL_DENUM_MASK			(0x1f << 8)
#define SCU_D2_PLL_SET_NUM(x)			(x)
#define SCU_D2_PLL_GET_NUM(x)			(x & 0xff)
#define SCU_D2_PLL_NUM_MASK				(0xff)


/*	AST_SCU_M_PLL : 0x20	- M-PLL Parameter register	*/
#define SCU_M_PLL_BYPASS_EN				(0x1 << 17)
#define SCU_M_PLL_OFF					(0x1 << 16)
#define SCU_M_PLL_NUM(x)				(x << 5)
#define SCU_M_PLL_GET_NUM(x)			((x >> 5) & 0x3f)
#define SCU_M_PLL_NUM_MASK				(0x3f << 5)
#define SCU_M_PLL_OUT_DIV				(0x1 << 4)
#define SCU_M_PLL_GET_DIV(x)			((x >> 4) & 0x1)
#define SCU_M_PLL_DENUM(x)				(x)
#define SCU_M_PLL_GET_DENUM(x)			(x & 0xf)


/*	AST_SCU_H_PLL: 0x24- H-PLL Parameter register		*/
#if defined(CONFIG_ARCH_AST1010)
#define SCU_H_PLL_MASK_EN				(0x1 << 10)
#define SCU_H_PLL_REST_EN				(0x1 << 9)
#define SCU_H_PLL_OUT_DIV(x)			(x << 7)
#define SCU_H_PLL_GET_DIV(x)			((x >> 7) & 0x3)
#define SCU_H_PLL_GET_DENUM(x)			((x >> 6) & 0x1)
#define SCU_H_PLL_NUM(x)				(x)
#define SCU_H_PLL_GET_NUM(x)			(x & 0x3f)
#define SCU_H_PLL_NUM_MASK				(0x3f)

#else
#define SCU_H_PLL_PARAMETER				(0x1 << 18)
#define SCU_H_PLL_BYPASS_EN				(0x1 << 17)
#define SCU_H_PLL_OFF					(0x1 << 16)
#define SCU_H_PLL_NUM(x)				(x << 5)
#define SCU_H_PLL_GET_NUM(x)			((x >> 5) & 0x3f)
#define SCU_H_PLL_NUM_MASK				(0x3f << 5)
#define SCU_H_PLL_OUT_DIV				(0x1 << 4)
#define SCU_H_PLL_GET_DIV(x)			((x >> 4) & 0x1)
#define SCU_H_PLL_DENUM(x)				(x)
#define SCU_H_PLL_GET_DENUM(x)			(x & 0xf)
#define SCU_H_PLL_DENUM_MASK			(0xf)
#endif

/*	AST_SCU_FREQ_LIMIT : 0x28 - frequency counter comparsion register */
#define SCU_FREQ_U_LIMIT(x)			(x << 16)
#define SCU_FREQ_U_LIMIT_MASK		(0x3fff << 16)
#define SCU_FREQ_L_LIMIT(x)			(x)
#define SCU_FREQ_L_LIMIT_MASK		(0x3fff)


/*	AST_SCU_MISC_CTRL : 0x2C - Misc. Control register */
#define SCU_MISC_JTAG_MASTER_DIS	(0x1 << 26)
#define SCU_MISC_DRAM_W_P2A_DIS		(0x1 << 25)
#define SCU_MISC_SPI_W_P2A_DIS		(0x1 << 24)
#define SCU_MISC_SOC_W_P2A_DIS		(0x1 << 23)
#define SCU_MISC_FLASH_W_P2A_DIS	(0x1 << 22)
#define SCU_MISC_D_PLL_ASSIGN(x)	(x << 20)
#define SCU_MISC_D_PLL_ASSIGN_MASK	(0x3 << 20)
#define SCU_MISC_VGA_CONFIG_PREFETCH	(0x1 << 19)
#define SCU_MISC_DVO_SOURCE_CRT			(0x1 << 18) 	//0:VGA , 1:CRT
#define SCU_MISC_DAC_MASK				(0x3 << 16)
#define SCU_MISC_DAC_SOURCE_CRT			(0x1 << 16)		//00 VGA, 01: CRT, 1x: PASS-Through DVO
#define SCU_MISC_DAC_SOURCE_MASK		(0x3 << 16)		
#define SCU_MISC_JTAG_TO_PCIE_EN		(0x1 << 15)
#define SCU_MISC_JTAG__M_TO_PCIE_EN		(0x1 << 14)
#define SCU_MISC_VUART_TO_CTRL			(0x1 << 13)
#define SCU_MISC_DIV13_EN				(0x1 << 12)
#define SCU_MISC_Y_CLK_INVERT			(0x1 << 11)
#define SCU_MISC_OUT_DELAY				(0x1 << 9)
#define SCU_MISC_PCI_TO_AHB_DIS			(0x1 << 8)
#define SCU_MISC_2D_CRT_EN				(0x1 << 7)
#define SCU_MISC_VGA_CRT_DIS			(0x1 << 6)
#define SCU_MISC_VGA_REG_ACCESS_EN		(0x1 << 5)
#define SCU_MISC_D2_PLL_DIS				(0x1 << 4)
#define SCU_MISC_DAC_DIS				(0x1 << 3)
#define SCU_MISC_D_PLL_DIS				(0x1 << 2)
#define SCU_MISC_OSC_CLK_OUT_PIN		(0x1 << 1)
#define SCU_MISC_LPC_TO_SPI_DIS			(0x1 << 0)

/*	AST_SCU_PCI_CONF1 : 0x30 - PCI configuration setting register#1 */
#define SCU_PCI_DEVICE_ID(x)			(x << 16)
#define SCU_PCI_VENDOR_ID(x)			(x)

/*	AST_SCU_PCI_CONF2	0x34		PCI configuration setting register#2 */
#define SCU_PCI_SUB_SYS_ID(x)			(x << 16)
#define SCU_PCI_SUB_VENDOR_ID(x)		(x)

/*	AST_SCU_PCI_CONF3	0x38		PCI configuration setting register#3 */
#define SCU_PCI_CLASS_CODE(x)			(x << 8)
#define SCU_PCI_REVISION_ID(x)			(x)

/*	AST_SCU_SYS_CTRL	0x3C		System reset contrl/status register*/
#define SCU_SYS_EXT_SOC_RESET_EN		(0x1 << 3)
#define SCU_SYS_EXT_RESET_FLAG			(0x1 << 2)
#define SCU_SYS_WDT_RESET_FLAG			(0x1 << 1)
#define SCU_SYS_PWR_RESET_FLAG			(0x1 << 0)

/*	AST_SCU_SOC_SCRATCH0	0x40		SOC scratch 0~31 register */




/*	AST_SCU_SOC_SCRATCH1	0x44		SOC scratch 32~63 register */


/*	AST_SCU_VGA0		0x40		VGA fuction handshake register */
#define SCU_VGA_SLT_HANDSHAKE(x)		(x << 24)
#define SCU_VGA_SLT_HANDSHAKE_MASK		(0xff << 24)
#define SCU_VGA_CTM_DEF(x)				(x << 16)
#define SCU_VGA_CTM_DEF_MASK			(0xff << 16)
#define SCU_MAC0_PHY_MODE(x)			(x << 14)
#define SCU_MAC0_GET_PHY_MODE(x)		((x >> 14) & 0x3)
#define SCU_MAC0_PHY_MODE_MASK(x)		(0x3 << 14)
#define SCU_MAC1_PHY_MODE(x)			(x << 12)
#define SCU_MAC1_PHY_MODE_MASK			(0x3 << 12)
#define SCU_MAC1_GET_PHY_MODE(x)		((x >> 12) & 0x3)

#define SCU_VGA_ASPEED_DEF(x)			(x << 8)
#define SCU_VGA_ASPEED_DEF_MASK			(0xf << 8)

#define SCU_VGA_DRAM_INIT_MASK(x)		((x >> 7) & 0x1)

/*	AST_SCU_VGA1		0x44		VGA fuction handshake register */


/*	AST_SCU_MAC_CLK		0x48		MAC interface clock delay setting register */



/*	AST_SCU_MISC_CTRL	0x4C		Misc. 2 Control register */
/*	AST_SCU_VGA_SCRATCH0	0x50		VGA Scratch register */
/*	AST_SCU_VGA_SCRATCH1	0x54		VGA Scratch register */
/*	AST_SCU_VGA_SCRATCH2	0x58		VGA Scratch register */
/*	AST_SCU_VGA_SCRATCH3	0x5c		VGA Scratch register */
/*	AST_SCU_VGA_SCRATCH4	0x60		VGA Scratch register */
/*	AST_SCU_VGA_SCRATCH5	0x64		VGA Scratch register */
/*	AST_SCU_VGA_SCRATCH6	0x68		VGA Scratch register */
/*	AST_SCU_VGA_SCRATCH7	0x6c		VGA Scratch register */

/*	AST_SCU_HW_STRAP1			0x70		hardware strapping register */
#define SCU_HW_STRAP_SW_DEFINE(x)		(x << 29)
#define SCU_HW_STRAP_SW_DEFINE_MASK		(0x3 << 29)
#define SCU_HW_STRAP_DRAM_SIZE			(x << 29)
#define SCU_HW_STRAP_DRAM_SIZE_MASK		(0x3 << 29)

#define VGA_64M_DRAM			0
#define VGA_128M_DRAM			1
#define VGA_256M_DRAM			2
#define VGA_512M_DRAM			3

#define SCU_HW_STRAP_DRAM_CONFIG		(x << 24)
#define SCU_HW_STRAP_DRAM_CONFIG_MASK	(0x7 << 24)

#define SCU_HW_STRAP_GPIOE_PT_EN		(0x1 << 22)
#define SCU_HW_STRAP_GPIOD_PT_EN		(0x1 << 21)
#define SCU_HW_STRAP_LPC_DEC_SUPER_IO	(0x1 << 20)
#define SCU_HW_STRAP_ACPI_DIS			(0x1 << 19)

//bit 23, 18 [1,0]
#define SCU_HW_STRAP_SET_CLK_SOURCE(x)		((((x&0x3) >> 1)<<23)||((x&0x1) << 18))
#define SCU_HW_STRAP_GET_CLK_SOURCE(x)		(((x>>23)&0x1<<1) | ((x>>18)&0x1))
#define SCU_HW_STRAP_CLK_SOURCE_MASK		((0x1 << 23) | (0x1 << 18))

#define CLK_25M_IN					(0x1 << 23)
#define CLK_24M_IN					0
#define CLK_48M_IN					1
#define CLK_25M_IN_24M_USB_CKI		3
#define CLK_25M_IN_48M_USB_CKI		3

#define SCU_HW_STRAP_2ND_BOOT_WDT		(0x1 << 17)
#define SCU_HW_STRAP_SUPER_IO_CONFIG	(0x1 << 16)
#define SCU_HW_STRAP_VGA_CLASS_CODE		(0x1 << 15)
#define SCU_HW_STRAP_LPC_RESET_PIN		(0x1 << 14)
#define SCU_HW_STRAP_SPI_MODE(x)			(x << 12)
#define SCU_HW_STRAP_SPI_MODE_MASK			(0x3 << 12)
#define SPI_MODE_DIS			(0)
#define SPI_MODE_MASTER_EN		(1)
#define SPI_MODE_M_S_EN			(2)
#define SPI_MODE_PS				(3)

#define SCU_HW_STRAP_SET_CPU_AHB_RATIO(x)		(x << 10)
#define SCU_HW_STRAP_GET_CPU_AHB_RATIO(x)		((x >> 10) & 3)
#define SCU_HW_STRAP_CPU_AHB_RATIO_MASK		(0x3 << 10)


#define CPU_AHB_RATIO_1_1		0
#define CPU_AHB_RATIO_2_1		1
#define CPU_AHB_RATIO_4_1		2
#define CPU_AHB_RATIO_3_1		3

#if defined(CONFIG_ARCH_AST2300) || defined(CONFIG_ARCH_AST2400)
#define SCU_HW_STRAP_GET_H_PLL_CLK(x)		((x >> 8) & 0x3)
#define SCU_HW_STRAP_H_PLL_CLK_MASK		(0x3 << 8)
#define CPU_384MHZ		0
#define CPU_360MHZ		1
#define CPU_336MHZ		2
#define CPU_408MHZ		3
#else
#define SCU_HW_STRAP_GET_H_PLL_CLK(x)		((x >> 9) & 0x7)
#define SCU_HW_STRAP_H_PLL_CLK_MASK		(0x7 << 9)
#define CPU_100MHZ		5
#define CPU_133MHZ		4
#define CPU_166MHZ		3
#define CPU_200MHZ		2
#endif

#if defined(CONFIG_ARCH_AST2300) || defined(CONFIG_ARCH_AST2400)
#define SCU_HW_STRAP_MAC1_RGMII		(0x1 << 7)
#define SCU_HW_STRAP_MAC0_RGMII		(0x1 << 6)
#else
#define SCU_HW_STRAP_MAC_CONFIG		(0x7 << 6)
#define SCU_HW_STRAP_MAC0_RGMII		(0x1 << 8)
#endif
#define SCU_HW_STRAP_VGA_BIOS_ROM	(0x1 << 5)
#define SCU_HW_STRAP_SPI_WIDTH		(0x1 << 4)
#define SCU_HW_STRAP_VGA_SIZE_GET(x)		((x >> 2)& 0x3)

#define SCU_HW_STRAP_BOOT_MODE(x)		(x)
#define NOR_BOOT		0
#define NAND_BOOT		1
#define SPI_BOOT		2
#define DIS_BOOT		3

/*	AST_SCU_RAMDOM_GEN		0x74		random number generator register */
/*	AST_SCU_RAMDOM_DATA		0x78		random number generator data output*/

/*	AST_SCU_MULTI_FUNC_2	0x78 */

#define MULTI_FUNC_VIDEO_RGB18			(0x1 << 2)
#define MULTI_FUNC_VIDEO_SINGLE_EDGE	(0x1 << 0)



/*	AST_SCU_REVISION_ID		0x7C		Silicon revision ID register */
#define AST1100_A0				0x00000200
#define AST1100_A1				0x00000201
#define AST1100_A2				0x00000202
#define AST1100_A3				0x00000202

#define AST2050_A0				0x00000200
#define AST2050_A1				0x00000201
#define AST2050_A2				0x00000202
#define AST2050_A3				0x00000202

#define AST2100_A0				0x00000300
#define AST2100_A1				0x00000301
#define AST2100_A2				0x00000302
#define AST2100_A3				0x00000302

#define AST2200_A0				0x00000102
#define AST2200_A1				0x00000102

#define AST2300_A0				0x01000003
#define AST2300_A1				0x01010303
#define AST1300_A1				0x01010003
#define AST1050_A1				0x01010203

#define AST2400_A0				0x02000303


/*	AST_SCU_FUN_PIN_CTRL1		0x80		Multi-function Pin Control#1*/
#define SCU_FUN_PIN_UART4_RXD	(0x1 << 31)
#define SCU_FUN_PIN_UART4_TXD	(0x1 << 30)
#define SCU_FUN_PIN_UART4_NRTS	(0x1 << 29)
#define SCU_FUN_PIN_UART4_NDTR	(0x1 << 28)
#define SCU_FUN_PIN_UART4_NRI	(0x1 << 27)
#define SCU_FUN_PIN_UART4_NDSR	(0x1 << 26)
#define SCU_FUN_PIN_UART4_NDCD	(0x1 << 25)
#define SCU_FUN_PIN_UART4_NCTS	(0x1 << 24)
#define SCU_FUN_PIN_UART3_RXD	(0x1 << 23)
#define SCU_FUN_PIN_UART3_TXD	(0x1 << 22)
#define SCU_FUN_PIN_UART3_NRTS	(0x1 << 21)
#define SCU_FUN_PIN_UART3_NDTR	(0x1 << 20)
#define SCU_FUN_PIN_UART3_NRI	(0x1 << 19)
#define SCU_FUN_PIN_UART3_NDSR	(0x1 << 18)
#define SCU_FUN_PIN_UART3_NDCD	(0x1 << 17)
#define SCU_FUN_PIN_UART3_NCTS	(0x1 << 16)

#if defined(CONFIG_ARCH_2300) || defined(CONFIG_ARCH_2400)
#define SCU_FUN_PIN_MAC1_PHY_LINK	(0x1 << 1)
#define SCU_FUN_PIN_MAC0_PHY_LINK	(0x1)
#else
#define SCU_FUN_PIN_MAC0_PHY_LINK	(0x1 << 25)
#endif


/*	AST_SCU_FUN_PIN_CTRL2		0x84		Multi-function Pin Control#2*/
#define SCU_FUN_PIN_VPIB9		(0x1 << 31)
#define SCU_FUN_PIN_VPIB8		(0x1 << 30)
#define SCU_FUN_PIN_VPIB7		(0x1 << 29)
#define SCU_FUN_PIN_VPIB6		(0x1 << 28)
#define SCU_FUN_PIN_VPIB5		(0x1 << 27)
#define SCU_FUN_PIN_VPIB4		(0x1 << 26)
#define SCU_FUN_PIN_VPIB3		(0x1 << 25)
#define SCU_FUN_PIN_VPIB2		(0x1 << 24)
#define SCU_FUN_PIN_VPIB1		(0x1 << 23)
#define SCU_FUN_PIN_VPIB0		(0x1 << 22)
#define SCU_FUN_PIN_VPICLK		(0x1 << 21)
#define SCU_FUN_PIN_VPIVS		(0x1 << 20)
#define SCU_FUN_PIN_VPIHS		(0x1 << 19)
#define SCU_FUN_PIN_VPIODD		(0x1 << 18)
#define SCU_FUN_PIN_VPIDE		(0x1 << 17)

#define SCU_FUN_PIN_UART2_RXD	(0x1 << 31)
#define SCU_FUN_PIN_UART2_TXD	(0x1 << 30)
#define SCU_FUN_PIN_UART2_NRTS	(0x1 << 29)
#define SCU_FUN_PIN_UART2_NDTR	(0x1 << 28)
#define SCU_FUN_PIN_UART2_NRI	(0x1 << 27)
#define SCU_FUN_PIN_UART2_NDSR	(0x1 << 26)
#define SCU_FUN_PIN_UART2_NDCD	(0x1 << 25)
#define SCU_FUN_PIN_UART2_NCTS	(0x1 << 24)
#define SCU_FUN_PIN_UART1_RXD	(0x1 << 23)
#define SCU_FUN_PIN_UART1_TXD	(0x1 << 22)
#define SCU_FUN_PIN_UART1_NRTS	(0x1 << 21)
#define SCU_FUN_PIN_UART1_NDTR	(0x1 << 20)
#define SCU_FUN_PIN_UART1_NRI	(0x1 << 19)
#define SCU_FUN_PIN_UART1_NDSR	(0x1 << 18)
#define SCU_FUN_PIN_UART1_NDCD	(0x1 << 17)
#define SCU_FUN_PIN_UART1_NCTS	(0x1 << 16)


#define SCU_FUN_PIN_NAND_FLWP	(0x1 << 7)
#define SCU_FUN_PIN_NAND_FLBUSY	(0x1 << 6)

/*	AST_SCU_FUN_PIN_CTRL3		0x88		Multi-function Pin Control#3*/
#if	defined(CONFIG_ARCH_AST1010)
#define SCU_FUN_PIN_MAC0_MDIO	(0x1 << 23)
#define SCU_FUN_PIN_MAC0_MDC	(0x1 << 22)
#else
#define SCU_FUN_PIN_MAC0_MDIO	(0x1 << 31)
#define SCU_FUN_PIN_MAC0_MDC	(0x1 << 30)
#define SCU_FUN_PIN_ROMA25		(0x1 << 29)
#define SCU_FUN_PIN_ROMA24		(0x1 << 28)
#define SCU_FUN_PIN_ROMCS4		(0x1 << 27)
#define SCU_FUN_PIN_ROMCS3		(0x1 << 26)
#define SCU_FUN_PIN_ROMCS2		(0x1 << 25)
#define SCU_FUN_PIN_ROMCS1		(0x1 << 24)
#define SCU_FUN_PIN_ROMCS(x)	(0x1 << (23+x))

//Video pin
#define SCU_FUN_PIN_VPIR9		(0x1 << 19)
#define SCU_FUN_PIN_VPIR8		(0x1 << 18)
#define SCU_FUN_PIN_VPIR7		(0x1 << 17)
#define SCU_FUN_PIN_VPIR6		(0x1 << 16)
#define SCU_FUN_PIN_VPIR5		(0x1 << 15)
#define SCU_FUN_PIN_VPIR4		(0x1 << 14)
#define SCU_FUN_PIN_VPIR3		(0x1 << 13)
#define SCU_FUN_PIN_VPIR2		(0x1 << 12)
#define SCU_FUN_PIN_VPIR1		(0x1 << 11)
#define SCU_FUN_PIN_VPIR0		(0x1 << 10)
#define SCU_FUN_PIN_VPIG9		(0x1 << 9)
#define SCU_FUN_PIN_VPIG8		(0x1 << 8)
#define SCU_FUN_PIN_VPIG7		(0x1 << 7)
#define SCU_FUN_PIN_VPIG6		(0x1 << 6)
#define SCU_FUN_PIN_VPIG5		(0x1 << 5)
#define SCU_FUN_PIN_VPIG4		(0x1 << 4)
#define SCU_FUN_PIN_VPIG3		(0x1 << 3)
#define SCU_FUN_PIN_VPIG2		(0x1 << 2)
#define SCU_FUN_PIN_VPIG1		(0x1 << 1)
#define SCU_FUN_PIN_VPIG0		(0x1 << 0)
#endif


//pwm pin
#define SCU_FUN_PIN_PWM_TACHO	(0)
/*	AST_SCU_FUN_PIN_CTRL4		0x8C		Multi-function Pin Control#4*/
#define SCU_FUN_PIN_ROMA23		(0x1 << 7)
#define SCU_FUN_PIN_ROMA22		(0x1 << 6)

#define SCU_FUN_PIN_ROMWE		(0x1 << 5)
#define SCU_FUN_PIN_ROMOE		(0x1 << 4)
#define SCU_FUN_PIN_ROMD7		(0x1 << 3)
#define SCU_FUN_PIN_ROMD6		(0x1 << 2)
#define SCU_FUN_PIN_ROMD5		(0x1 << 1)
#define SCU_FUN_PIN_ROMD4		(0x1)

/*	AST_SCU_FUN_PIN_CTRL5		0x90		Multi-function Pin Control#5*/
#define SCU_FUN_PIN_SPICS1		(0x1 << 31)
#define SCU_FUN_PIN_LPC_PLUS	(0x1 << 30)
#define SCU_FUC_PIN_USB20_HOST	(0x1 << 29)
#define SCU_FUC_PIN_USB11_PORT4	(0x1 << 28)
#define SCU_FUC_PIN_I2C14		(0x1 << 27)
#define SCU_FUC_PIN_I2C13		(0x1 << 26)
#define SCU_FUC_PIN_I2C12		(0x1 << 25)
#define SCU_FUC_PIN_I2C11		(0x1 << 24)
#define SCU_FUC_PIN_I2C10		(0x1 << 23)
#define SCU_FUC_PIN_I2C9		(0x1 << 22)
#define SCU_FUC_PIN_I2C8		(0x1 << 21)
#define SCU_FUC_PIN_I2C7		(0x1 << 20)
#define SCU_FUC_PIN_I2C6		(0x1 << 19)
#define SCU_FUC_PIN_I2C5		(0x1 << 18)
#define SCU_FUC_PIN_I2C4		(0x1 << 17)
#define SCU_FUC_PIN_I2C3		(0x1 << 16)
#define SCU_FUC_PIN_MII2_RX_DWN_DIS		(0x1 << 15)
#define SCU_FUC_PIN_MII2_TX_DWN_DIS		(0x1 << 14)
#define SCU_FUC_PIN_MII1_RX_DWN_DIS		(0x1 << 13)
#define SCU_FUC_PIN_MII1_TX_DWN_DIS		(0x1 << 12)

#define SCU_FUC_PIN_MII2_TX_DRIV(x)		(x << 10)
#define SCU_FUC_PIN_MII2_TX_DRIV_MASK	(0x3 << 10)
#define SCU_FUC_PIN_MII1_TX_DRIV(x)		(x << 8)
#define SCU_FUC_PIN_MII1_TX_DRIV_MASK	(0x3 << 8)

#define MII_NORMAL_DRIV	0x0
#define MII_HIGH_DRIV	0x2

#define SCU_FUC_PIN_UART6		(0x1 << 7)
#define SCU_FUC_PIN_ROM_16BIT	(0x1 << 6)
#define SCU_FUC_PIN_DIGI_V_OUT(x)	(x << 4)
#define SCU_FUC_PIN_DIGI_V_OUT_MASK	(0x3 << 4)

#define VIDEO_DISABLE	0x0
#define VIDEO_12BITS	0x1
#define VIDEO_24BITS	0x2
//#define VIDEO_DISABLE	0x3

#define SCU_FUC_PIN_USB11_PORT2	(0x1 << 3)
#define SCU_FUC_PIN_MAC1_MDIO		(0x1 << 2)
#define SCU_FUC_PIN_SD2		(0x1 << 1)
#define SCU_FUC_PIN_SD1		(0x1 << 0)


/*	AST_SCU_FUN_PIN_CTRL6		0x94		Multi-function Pin Control#6*/
#define SCU_VIDEO_OUT_MASK		(~0x3)

/*	AST_SCU_WDT_RESET		0x9C		Watchdog Reset Selection */
/*	AST_SCU_FUN_PIN_CTRL7		0xA0		Multi-function Pin Control#7*/
/*	AST_SCU_FUN_PIN_CTRL8		0xA4		Multi-function Pin Control#8*/
#define SCU_FUN_PIN_ROMA17		(0x1 << 31)
#define SCU_FUN_PIN_ROMA16		(0x1 << 30)
#define SCU_FUN_PIN_ROMA15		(0x1 << 29)
#define SCU_FUN_PIN_ROMA14		(0x1 << 28)
#define SCU_FUN_PIN_ROMA13		(0x1 << 27)
#define SCU_FUN_PIN_ROMA12		(0x1 << 26)
#define SCU_FUN_PIN_ROMA11		(0x1 << 25)
#define SCU_FUN_PIN_ROMA10		(0x1 << 24)
#define SCU_FUN_PIN_ROMA9		(0x1 << 23)
#define SCU_FUN_PIN_ROMA8		(0x1 << 22)
#define SCU_FUN_PIN_ROMA7		(0x1 << 21)
#define SCU_FUN_PIN_ROMA6		(0x1 << 20)
#define SCU_FUN_PIN_ROMA5		(0x1 << 19)
#define SCU_FUN_PIN_ROMA4		(0x1 << 18)
#define SCU_FUN_PIN_ROMA3		(0x1 << 17)
#define SCU_FUN_PIN_ROMA2		(0x1 << 16)

/*	AST_SCU_FUN_PIN_CTRL9		0xA8		Multi-function Pin Control#9*/
#define SCU_FUN_PIN_ROMA21		(0x1 << 3)
#define SCU_FUN_PIN_ROMA20		(0x1 << 2)
#define SCU_FUN_PIN_ROMA19		(0x1 << 1)
#define SCU_FUN_PIN_ROMA18		(0x1)

/*	AST_SCU_PWR_SAVING_EN		0xC0		Power Saving Wakeup Enable*/
/*	AST_SCU_PWR_SAVING_CTRL		0xC4		Power Saving Wakeup Control*/
/*	AST_SCU_HW_STRAP2			0xD0		Haardware strapping register set 2*/
/*	AST_SCU_COUNTER4			0xE0		SCU Free Run Counter Read Back #4*/
/*	AST_SCU_COUNTER4_EXT		0xE4		SCU Free Run Counter Extended Read Back #4*/

//CPU 2 
/*	AST_SCU_CPU2_CTRL			0x100		CPU2 Control Register*/
/*	AST_SCU_CPU2_BASE0_ADDR		0x104		CPU2 Base Address for Segment 0x00:0000~0x1F:FFFF*/
/*	AST_SCU_CPU2_BASE1_ADDR		0x108		CPU2 Base Address for Segment 0x20:0000~0x3F:FFFF*/
/*	AST_SCU_CPU2_BASE2_ADDR		0x10C		CPU2 Base Address for Segment 0x40:0000~0x5F:FFFF*/
/*	AST_SCU_CPU2_BASE3_ADDR		0x110		CPU2 Base Address for Segment 0x60:0000~0x7F:FFFF*/
/*	AST_SCU_CPU2_BASE4_ADDR		0x114		CPU2 Base Address for Segment 0x80:0000~0xFF:FFFF*/
/*	AST_SCU_CPU2_CACHE_CTRL		0x118		CPU2 Cache Function Control */

//
/*	AST_SCU_UART24_REF			0x160		Generate UART 24Mhz Ref from H-PLL when CLKIN is 25Mhz */
/*	AST_SCU_PCIE_CONFIG_SET		0x180		PCI-E Configuration Setting Control Register */
/*	AST_SCU_BMC_MMIO_DEC		0x184		BMC MMIO Decode Setting Register */
/*	AST_SCU_DEC_AREA1			0x188		1st relocated controller decode area location */
/*	AST_SCU_DEC_AREA2			0x18C		2nd relocated controller decode area location */
/*	AST_SCU_MBOX_DEC_AREA		0x190		Mailbox decode area location*/
/*	AST_SCU_SRAM_DEC_AREA0		0x194		Shared SRAM area decode location*/
/*	AST_SCU_SRAM_DEC_AREA1		0x198		Shared SRAM area decode location*/
/*	AST_SCU_BMC_CLASS			0x19C		BMC device class code and revision ID */
/*	AST_SCU_BMC_DEV_ID			0x1A4		BMC device ID */

#endif

