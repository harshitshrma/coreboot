/*
 * This file is part of the LinuxBIOS project.
 *
 * Copyright (C) 2007 Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <console.h>
#include <io.h>
#include <msr.h>
#include <amd_geodelx.h>
#include "cs5536.h"

/*
 * Early chipset initialization for the AMD CS5536 Companion Device.
 *
 * This code is needed for setting up RAM, since we need SMBus working as
 * well as a serial port.
 *
 * This file implements the initialization sequence documented in section 4.2
 * of AMD Geode GX Processor CS5536 Companion Device GoedeROM Porting Guide.
 */

/**
 * Set up GLINK routing for this part.
 *
 * The routing is controlled by an MSR. This appears to be the same on
 * all boards.
 */
void cs5536_setup_extmsr(void)
{
	struct msr  msr;

	/* Forward MSR access to CS5536_GLINK_PORT_NUM to CS5536_DEV_NUM. */
	msr.hi = msr.lo = 0x00000000;

#if CS5536_GLINK_PORT_NUM <= 4
	msr.lo = CS5536_DEV_NUM <<
	    (unsigned char)((CS5536_GLINK_PORT_NUM - 1) * 8);
#else
	msr.hi = CS5536_DEV_NUM <<
	    (unsigned char)((CS5536_GLINK_PORT_NUM - 5) * 8);
#endif

	wrmsr(GLPCI_ExtMSR, msr);
}

/**
 * Setup PCI IDSEL for CS5536. There is a Magic Register that must be
 * written so that the chip appears at the expected place in the PCI tree.
 */
void cs5536_setup_idsel(void)
{
	/* Write IDSEL to the write once register at address 0x0000. */
	outl(0x1 << (CS5536_DEV_NUM + 10), 0);
}

/**
 * Magic Bits for undocumented register. You don't need to see those papers.
 * These are not the bits you're looking for. You can go about your business.
 * Move along, move along.
 */
void cs5536_usb_swapsif(void)
{
	struct msr  msr;

	msr = rdmsr(USB1_SB_GLD_MSR_CAP + 0x5);

	/* USB Serial short detect bit. */
	if (msr.hi & 0x10) {
		/* We need to preserve bits 32,33,35 and not clear any BIST
		 * error, but clear the SERSHRT error bit.
		 */
		msr.hi &= 0xFFFFFFFB;
		wrmsr(USB1_SB_GLD_MSR_CAP + 0x5, msr);
	}
}

/**
 * Set up I/O bases for SMBus, GPIO, MFGPT, ACPI, and PM.
 *
 * These can be changed by Linux later. We set some initial value so that
 * the resources are there as needed. The values are hardcoded because,
 * this early in the process, fancy allocation can do more harm than good.
 */
void cs5536_setup_iobase(void)
{
	struct msr  msr;

	/* Setup LBAR for SMBus controller. */
	msr.hi = 0x0000f001;
	msr.lo = SMBUS_IO_BASE;
	wrmsr(MDD_LBAR_SMB, msr);

	/* Setup LBAR for GPIO. */
	msr.hi = 0x0000f001;
	msr.lo = GPIO_IO_BASE;
	wrmsr(MDD_LBAR_GPIO, msr);

	/* Setup LBAR for MFGPT. */
	msr.hi = 0x0000f001;
	msr.lo = MFGPT_IO_BASE;
	wrmsr(MDD_LBAR_MFGPT, msr);

	/* Setup LBAR for ACPI. */
	msr.hi = 0x0000f001;
	msr.lo = ACPI_IO_BASE;
	wrmsr(MDD_LBAR_ACPI, msr);

	/* Setup LBAR for PM support. */
	msr.hi = 0x0000f001;
	msr.lo = PMS_IO_BASE;
	wrmsr(MDD_LBAR_PMS, msr);
}

/**
 * Power Button Setup.
 *
 * Setup GPIO24, it is the external signal for CS5536 vsb_work_aux which
 * controls all voltage rails except Vstandby & Vmem. We need to enable,
 * OUT_AUX1 and OUTPUT_ENABLE in this order.
 *
 * If GPIO24 is not enabled then soft-off will not work.
 */
void cs5536_setup_power_button(void)
{
	outl(0x40020000, PMS_IO_BASE + 0x40);
	outl(GPIOH_24_SET, GPIO_IO_BASE + GPIOH_OUT_AUX1_SELECT);
	outl(GPIOH_24_SET, GPIO_IO_BASE + GPIOH_OUTPUT_ENABLE);
}

/**
 * Set the various GPIOs.
 *
 * An unknown question at this point is how general this is to all mainboards.
 * At the same time, many boards seem to follow this particular reference spec.
 */
void cs5536_setup_smbus_gpio(void)
{
	u32 val;

	/* Setup GPIO pins 14/15 for SDA/SCL. */
	val = GPIOL_15_SET | GPIOL_14_SET;

	/* Output Enable */
	outl(val, GPIO_IO_BASE + GPIOL_OUT_AUX1_SELECT);

	/* Output AUX1 */
	outl(val, GPIO_IO_BASE + GPIOL_OUTPUT_ENABLE);

	/* Input Enable */
	outl(val, GPIO_IO_BASE + GPIOL_IN_AUX1_SELECT);

	/* Input AUX1 */
	outl(val, GPIO_IO_BASE + GPIOL_INPUT_ENABLE);
}

/**
 * Disable the internal UART.
 *
 * Different boards have different UARTs for COM1.
 */
void cs5536_disable_internal_uart(void)
{
	struct msr  msr;

	/* The UARTs default to enabled.
	 * Disable and reset them and configure them later (SIO init).
	 */
	msr = rdmsr(MDD_UART1_CONF);
	msr.lo = 1;		// reset
	wrmsr(MDD_UART1_CONF, msr);
	msr.lo = 0;		// disabled
	wrmsr(MDD_UART1_CONF, msr);

	msr = rdmsr(MDD_UART2_CONF);
	msr.lo = 1;		// reset
	wrmsr(MDD_UART2_CONF, msr);
	msr.lo = 0;		// disabled
	wrmsr(MDD_UART2_CONF, msr);
}

/**
 * Set up the CS5536 CIS interface to CPU interface to match modes.
 *
 * The CIS is related to the interrupt system. It is important to match
 * the southbridge and the CPU chips. At the same time, they always seem
 * to use mode B.
 */
void cs5536_setup_cis_mode(void)
{
	struct msr  msr;

	/* Setup CPU interface serial to mode B to match CPU. */
	msr = rdmsr(GLPCI_SB_CTRL);
	msr.lo &= ~0x18;
	msr.lo |= 0x10;
	wrmsr(GLPCI_SB_CTRL, msr);
}

/**
 * Enable the on chip UART.
 *
 * See page 412 of the AMD Geode CS5536 Companion Device data book.
 */
void cs5536_setup_onchipuart(void)
{
	struct msr  msr;

	/* Setup early for polling only mode.
	 * 1. Eanble GPIO 8 to OUT_AUX1, 9 to IN_AUX1.
	 *        GPIO LBAR + 0x04, LBAR + 0x10, LBAR + 0x20, LBAR + 34
	 * 2. Enable UART I/O space in MDD.
	 *        MSR 0x51400014 bit 18:16
	 * 3. Enable UART controller.
	 *        MSR 0x5140003A bit 0, 1
	 */

	/* GPIO8 - UART1_TX */
	/* Set: Output Enable (0x4) */
	outl(GPIOL_8_SET, GPIO_IO_BASE + GPIOL_OUTPUT_ENABLE);
	/* Set: OUTAUX1 Select (0x10) */
	outl(GPIOL_8_SET, GPIO_IO_BASE + GPIOL_OUT_AUX1_SELECT);

	/* GPIO9 - UART1_RX */
	/* Set: Input Enable (0x20) */
	outl(GPIOL_9_SET, GPIO_IO_BASE + GPIOL_INPUT_ENABLE);
	/* Set: INAUX1 Select (0x34) */
	outl(GPIOL_9_SET, GPIO_IO_BASE + GPIOL_IN_AUX1_SELECT);

	/* Set address to 0x3F8. */
	msr = rdmsr(MDD_LEG_IO);
	msr.lo |= 0x7 << 16;
	wrmsr(MDD_LEG_IO, msr);

	/* Bit 1 = DEVEN (device enable)
	 * Bit 4 = EN_BANKS (allow access to the upper banks)
	 */
	msr.lo = (1 << 4) | (1 << 1);
	msr.hi = 0;

	/* Enable COM1. */
	wrmsr(MDD_UART1_CONF, msr);
}

/**
 * Board setup.
 *
 * Known to work on the AMD Norwich and DIGITIAL-LOGIC boards.
 *
 * The extmsr and cis_mode are common for sure. The RSTPLL check is mandatory.
 * IDSEL of course is required, so the chip appears in PCI config space,
 * and the swapsif covers a necessary chip fix.
 *
 * Finally, the iobase is needed for DRAM, the GPIOs are likely common to all
 * boards, and the power button seems to be the same on all. At the same time,
 * we may need to move GPIO and power button out as developments demand.
 *
 * Note we do NOT do any UART setup here -- this is done later by the
 * mainboard setup, since UART usage is not universal.
 *
 * See also a comment from Marc Jones:
 * http://www.linuxbios.org/pipermail/linuxbios/2007-June/021958.html
 */
void cs5536_early_setup(void)
{
	struct msr  msr;

	/* Note: you can't do prints in here in most cases, and we don't want
	 * to hang on serial, so they are commented out.
	 */
	cs5536_setup_extmsr();
	cs5536_setup_cis_mode();

	msr = rdmsr(GLCP_SYS_RSTPLL);
	if (msr.lo & (0x3f << 26)) {
		/* PLL is already set and we are reboot from PLL reset. */
		return;
	}

	cs5536_setup_idsel();
	cs5536_usb_swapsif();
	cs5536_setup_iobase();
	cs5536_setup_smbus_gpio();
	/* cs5536_enable_smbus(); -- Leave this out for now. */
	cs5536_setup_power_button();
}
