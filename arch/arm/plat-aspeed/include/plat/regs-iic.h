/* arch/arm/plat-aspeed/include/mach/regs-iic.h
 *
 * Copyright (c) 2012 ASPEED Technology Inc. <ryan_chen@aspeedtech.com>
 *		http://www.aspeedtech.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * ASPEED I2C Controller
*/

#ifndef __ASM_ARCH_REGS_IIC_H
#define __ASM_ARCH_REGS_IIC_H __FILE__

#ifdef CONFIG_ARCH_AST1010
#define AST_I2C_DMA_SIZE 512
#else
#define AST_I2C_DMA_SIZE 4096
#endif

#define AST_I2C_PAGE_SIZE 256

#if defined(CONFIG_ARCH_AST2300)
#define MASTER_XFER_MODE			BUFF_MODE
#define SLAVE_XFER_MODE				BYTE_MODE
#define NUM_BUS 9
#elif defined(CONFIG_ARCH_AST2400)
#define MASTER_XFER_MODE			BUFF_MODE
#define SLAVE_XFER_MODE				BYTE_MODE
#define NUM_BUS 14
#elif defined(CONFIG_ARCH_AST1010)
#define MASTER_XFER_MODE			BYTE_MODE
#define SLAVE_XFER_MODE				BYTE_MODE
#define NUM_BUS 15
#elif defined(CONFIG_ARCH_AST1520) || defined(CONFIG_ARCH_AST3200) || defined(CONFIG_ARCH_AST2500) || defined(CONFIG_ARCH_AST2100) || defined(CONFIG_ARCH_AST2050)
#define MASTER_XFER_MODE			BYTE_MODE
#define SLAVE_XFER_MODE				BYTE_MODE
#define NUM_BUS 4
#else
#error NO define NUM_BUS
#endif

#if defined(CONFIG_ARCH_AST1070)
#define AST_CI2C_GLOBAL_REG			0x00
#define AST_CI2C_DEVICE1			0x40
#define AST_CI2C_DEVICE2			0x80
#define AST_CI2C_DEVICE3			0xc0
#define AST_CI2C_DEVICE4			0x100
#define AST_CI2C_DEVICE5			0x140
#define AST_CI2C_DEVICE6			0x180
#define AST_CI2C_DEVICE7			0x1c0
#define AST_CI2C_DEVICE8			0x200
#endif

/*AST I2C Register Definition */
#if defined(CONFIG_ARCH_AST2400) || defined(CONFIG_AST2400_BMC)
#define AST_I2C_POOL_BUFF_2048
#define AST_I2C_GLOBAL_REG		0x00
#define AST_I2C_DEVICE1			0x40
#define AST_I2C_DEVICE2			0x80
#define AST_I2C_DEVICE3			0xc0
#define AST_I2C_DEVICE4			0x100
#define AST_I2C_DEVICE5			0x140
#define AST_I2C_DEVICE6			0x180
#define AST_I2C_DEVICE7			0x1c0
#define AST_I2C_BUFFER_POOL2	0x200
#define AST_I2C_DEVICE8			0x300
#define AST_I2C_DEVICE9			0x340
#define AST_I2C_DEVICE10		0x380
#define AST_I2C_DEVICE11		0x3c0
#define AST_I2C_DEVICE12		0x400
#define AST_I2C_DEVICE13		0x440
#define AST_I2C_DEVICE14		0x480
#define AST_I2C_BUFFER_POOL1	0x800

#elif defined(CONFIG_ARCH_AST2300)
#define AST_I2C_POOL_BUFF_256
#define AST_I2C_GLOBAL_REG		0x00
#define AST_I2C_DEVICE1			0x40
#define AST_I2C_DEVICE2			0x80
#define AST_I2C_DEVICE3			0xc0
#define AST_I2C_DEVICE4			0x100
#define AST_I2C_DEVICE5			0x140
#define AST_I2C_DEVICE6			0x180
#define AST_I2C_DEVICE7			0x1c0
#define AST_I2C_BUFFER_POOL2	0x200
#define AST_I2C_DEVICE8			0x300
#define AST_I2C_DEVICE9			0x340
#elif defined(CONFIG_ARCH_AST1010)
#define AST_I2C_GLOBAL_REG		0x00
#define AST_I2C_DEVICE1			0x40
#define AST_I2C_DEVICE2			0x80
#define AST_I2C_DEVICE3			0xc0
#define AST_I2C_DEVICE4			0x100
#define AST_I2C_DEVICE5			0x140
#define AST_I2C_DEVICE6			0x180
#define AST_I2C_DEVICE7			0x1c0
#define AST_I2C_DEVICE8			0x200
#define AST_I2C_DEVICE9			0x240
#define AST_I2C_DEVICE10		0x280
#define AST_I2C_DEVICE11		0x2c0
#define AST_I2C_DEVICE12		0x300
#define AST_I2C_DEVICE13		0x340
#define AST_I2C_DEVICE14		0x380
#define AST_I2C_DEVICE15		0x3c0
#elif defined(CONFIG_ARCH_AST2100) || defined(CONFIG_ARCH_AST2050)
#define AST_I2C_POOL_BUFF_256
#define AST_I2C_GLOBAL_REG		0x00
#define AST_I2C_DEVICE1			0x40
#define AST_I2C_DEVICE2			0x80
#define AST_I2C_DEVICE3			0xc0
#define AST_I2C_DEVICE4			0x100
#define AST_I2C_DEVICE5			0x140
#define AST_I2C_DEVICE6			0x180
#define AST_I2C_DEVICE7			0x1c0
#elif defined(CONFIG_ARCH_AST1520) || defined(CONFIG_ARCH_AST3200) || defined(CONFIG_ARCH_AST2500)
#define AST_I2C_GLOBAL_REG		0x00
#define AST_I2C_DEVICE1			0x40
#define AST_I2C_DEVICE2			0x80
#define AST_I2C_DEVICE3			0xc0
#define AST_I2C_DEVICE4			0x100
#else
#error NO define for I2C
#endif



/* I2C Register */
#define  I2C_FUN_CTRL_REG    		0x00
#define  I2C_AC_TIMING_REG1         	0x04
#define  I2C_AC_TIMING_REG2         	0x08
#define  I2C_INTR_CTRL_REG		0x0c
#define  I2C_INTR_STS_REG		0x10
#define  I2C_CMD_REG			0x14
#define  I2C_DEV_ADDR_REG		0x18
#define  I2C_BUF_CTRL_REG		0x1c
#define  I2C_BYTE_BUF_REG		0x20
#define  I2C_DMA_BASE_REG		0x24
#define  I2C_DMA_LEN_REG		0x28


/* Gloable Register Definition */
/* 0x00 : I2C Interrupt Status Register  */
/* 0x08 : I2C Interrupt Target Assignment  */
#if defined(CONFIG_ARCH_AST2400)
#define AST_I2CG_INTR14 		(0x1 << 13)
#define AST_I2CG_INTR13 		(0x1 << 12)
#define AST_I2CG_INTR12 		(0x1 << 11)
#define AST_I2CG_INTR11 		(0x1 << 10)
#define AST_I2CG_INTR10 		(0x1 << 9)
#elif defined(CONFIG_ARCH_AST1010)
#define AST_I2CG_INTR14 		(0x1 << 13)
#define AST_I2CG_INTR13 		(0x1 << 12)
#define AST_I2CG_INTR12 		(0x1 << 11)
#define AST_I2CG_INTR11 		(0x1 << 10)
#define AST_I2CG_INTR10 		(0x1 << 9)
#endif
#define AST_I2CG_INTR09 		(0x1 << 8)
#define AST_I2CG_INTR08 		(0x1 << 7)
#define AST_I2CG_INTR07 		(0x1 << 6)
#define AST_I2CG_INTR06	 		(0x1 << 5)
#define AST_I2CG_INTR05	 		(0x1 << 4)
#define AST_I2CG_INTR04 		(0x1 << 3)
#define AST_I2CG_INTR03	 		(0x1 << 2)
#define AST_I2CG_INTR02	 		(0x1 << 1)
#define AST_I2CG_INTR01	 		(0x1 )

/* Device Register Definition */
/* 0x00 : I2CD Function Control Register  */
#define AST_I2CD_BUFF_SEL_MASK				(0x7 << 20)
#define AST_I2CD_BUFF_SEL(x) 				(x << 20)		// page 0 ~ 7
#define AST_I2CD_M_SDA_LOCK_EN			(0x1 << 16)
#define AST_I2CD_MULTI_MASTER_DIS			(0x1 << 15)
#define AST_I2CD_M_SCL_DRIVE_EN		(0x1 << 14)
#define AST_I2CD_MSB_STS					(0x1 << 9)
#define AST_I2CD_SDA_DRIVE_1T_EN			(0x1 << 8)
#define AST_I2CD_M_SDA_DRIVE_1T_EN		(0x1 << 7)
#define AST_I2CD_M_HIGH_SPEED_EN		(0x1 << 6)
#define AST_I2CD_DEF_ADDR_EN				(0x1 << 5)
#define AST_I2CD_DEF_ALERT_EN				(0x1 << 4)
#define AST_I2CD_DEF_ARP_EN					(0x1 << 3)
#define AST_I2CD_DEF_GCALL_EN				(0x1 << 2)
#define AST_I2CD_SLAVE_EN					(0x1 << 1)
#define AST_I2CD_MASTER_EN					(0x1 )

/* 0x04 : I2CD Clock and AC Timing Control Register #1 */
#define AST_I2CD_tBUF						(0x1 << 28) 	// 0~7 
#define AST_I2CD_tHDSTA						(0x1 << 24)		// 0~7 
#define AST_I2CD_tACST						(0x1 << 20)		// 0~7 
#define AST_I2CD_tCKHIGH					(0x1 << 16)		// 0~7 
#define AST_I2CD_tCKLOW						(0x1 << 12)		// 0~7 
#define AST_I2CD_tHDDAT						(0x1 << 10)		// 0~7 
#define AST_I2CD_CLK_TO_BASE_DIV			(0x1 << 8)		// 0~3
#define AST_I2CD_CLK_BASE_DIV				(0x1 )			// 0~0xf

/* 0x08 : I2CD Clock and AC Timing Control Register #2 */
#define AST_I2CD_tTIMEOUT					(0x1 )			// 0~7
#define AST_NO_TIMEOUT_CTRL					0x0


/* 0x0c : I2CD Interrupt Control Register  */
#define AST_I2CD_SDA_DL_TO_INTR_EN					(0x1 << 14)		
#define AST_I2CD_BUS_RECOVER_INTR_EN				(0x1 << 13)		
#define AST_I2CD_SMBUS_ALT_INTR_EN					(0x1 << 12)		
#define AST_I2CD_SLAVE_MATCH_INTR_EN				(0x1 << 7)		
#define AST_I2CD_SCL_TO_INTR_EN						(0x1 << 6)		
#define AST_I2CD_ABNORMAL_INTR_EN					(0x1 << 5)		
#define AST_I2CD_NORMAL_STOP_INTR_EN				(0x1 << 4)
#define AST_I2CD_ARBIT_LOSS_INTR_EN					(0x1 << 3)		
#define AST_I2CD_RX_DOWN_INTR_EN					(0x1 << 2)		
#define AST_I2CD_TX_NAK_INTR_EN						(0x1 << 1)		
#define AST_I2CD_TX_ACK_INTR_EN						(0x1 )		

/* 0x10 : I2CD Interrupt Status Register   : WC */
#define AST_I2CD_INTR_STS_SDA_DL_TO					(0x1 << 14)		
#define AST_I2CD_INTR_STS_BUS_RECOVER				(0x1 << 13)		
#define AST_I2CD_INTR_STS_SMBUS_ALT					(0x1 << 12)		
#define AST_I2CD_INTR_STS_SMBUS_ARP_ADDR			(0x1 << 11)		
#define AST_I2CD_INTR_STS_SMBUS_DEV_ALT				(0x1 << 10)		
#define AST_I2CD_INTR_STS_SMBUS_DEF_ADDR			(0x1 << 9)		
#define AST_I2CD_INTR_STS_GCALL_ADDR				(0x1 << 8)		
#define AST_I2CD_INTR_STS_SLAVE_MATCH				(0x1 << 7)		
#define AST_I2CD_INTR_STS_SCL_TO					(0x1 << 6)		
#define AST_I2CD_INTR_STS_ABNORMAL					(0x1 << 5)		
#define AST_I2CD_INTR_STS_NORMAL_STOP				(0x1 << 4)
#define AST_I2CD_INTR_STS_ARBIT_LOSS				(0x1 << 3)
#define AST_I2CD_INTR_STS_RX_DOWN					(0x1 << 2)		
#define AST_I2CD_INTR_STS_TX_NAK					(0x1 << 1)		
#define AST_I2CD_INTR_STS_TX_ACK					(0x1 )		

/* 0x14 : I2CD Command/Status Register   */
#define AST_I2CD_SDA_OE					(0x1 << 28)
#define AST_I2CD_SDA_O					(0x1 << 27)		
#define AST_I2CD_SCL_OE					(0x1 << 26)		
#define AST_I2CD_SCL_O					(0x1 << 25)		
#define AST_I2CD_TX_TIMING				(0x1 << 24)		// 0 ~3
#define AST_I2CD_TX_STATUS				(0x1 << 23)		
// Tx State Machine 
#define AST_I2CD_IDLE	 				0x0
#define AST_I2CD_MACTIVE				0x8
#define AST_I2CD_MSTART					0x9
#define AST_I2CD_MSTARTR				0xa
#define AST_I2CD_MSTOP					0xb
#define AST_I2CD_MTXD					0xc
#define AST_I2CD_MRXACK					0xd
#define AST_I2CD_MRXD 					0xe
#define AST_I2CD_MTXACK 				0xf
#define AST_I2CD_SWAIT					0x1
#define AST_I2CD_SRXD 					0x4
#define AST_I2CD_STXACK 				0x5
#define AST_I2CD_STXD					0x6
#define AST_I2CD_SRXACK 				0x7
#define AST_I2CD_RECOVER 				0x3

#define AST_I2CD_SCL_LINE_STS				(0x1 << 18)		
#define AST_I2CD_SDA_LINE_STS				(0x1 << 17)		
#define AST_I2CD_BUS_BUSY_STS				(0x1 << 16)		
#define AST_I2CD_SDA_OE_OUT_DIR				(0x1 << 15)		
#define AST_I2CD_SDA_O_OUT_DIR				(0x1 << 14)		
#define AST_I2CD_SCL_OE_OUT_DIR				(0x1 << 13)		
#define AST_I2CD_SCL_O_OUT_DIR				(0x1 << 12)		
#define AST_I2CD_BUS_RECOVER_CMD_EN			(0x1 << 11)		
#define AST_I2CD_S_ALT_EN				(0x1 << 10)		
// 0 : DMA Buffer, 1: Pool Buffer
//AST1070 DMA register 
#define AST_I2CD_RX_DMA_ENABLE				(0x1 << 9)		
#define AST_I2CD_TX_DMA_ENABLE				(0x1 << 8)		

/* Command Bit */
#define AST_I2CD_RX_BUFF_ENABLE				(0x1 << 7)		
#define AST_I2CD_TX_BUFF_ENABLE				(0x1 << 6)		
#define AST_I2CD_M_STOP_CMD					(0x1 << 5)		
#define AST_I2CD_M_S_RX_CMD_LAST			(0x1 << 4)		
#define AST_I2CD_M_RX_CMD					(0x1 << 3)		
#define AST_I2CD_S_TX_CMD					(0x1 << 2)		
#define AST_I2CD_M_TX_CMD					(0x1 << 1)		
#define AST_I2CD_M_START_CMD				(0x1 )		

/* 0x18 : I2CD Slave Device Address Register   */

/* 0x1C : I2CD Pool Buffer Control Register   */
#define AST_I2CD_RX_BUF_ADDR_GET(x)				((x>> 24)& 0xff)
#define AST_I2CD_RX_BUF_END_ADDR_SET(x)			(x << 16)		
#define AST_I2CD_TX_DATA_BUF_END_SET(x)			((x&0xff) << 8)		
#define AST_I2CD_TX_DATA_BUF_GET(x)			((x >>8) & 0xff)		
#define AST_I2CD_BUF_BASE_ADDR_SET(x)			(x & 0x3f)		

/* 0x20 : I2CD Transmit/Receive Byte Buffer Register   */
#define AST_I2CD_GET_MODE(x)					((x >> 8) & 0x1)		

#define AST_I2CD_RX_BYTE_BUFFER					(0xff << 8)		
#define AST_I2CD_TX_BYTE_BUFFER					(0xff )		


#endif /* __ASM_ARCH_REGS_IIC_H */
