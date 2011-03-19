/*
    Copyright (C) 2011  scotty2

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details. 

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// this is a ridiculously dirty torn up version of the g2 wpthis kernel module made to work on the thunderbolt with the wpthis loader,
// which is pretty much a stripped down version of gfree (sans partition 7 writing code, as it appears to be permanently write protected on the thunderbolt)
// this module requires a radio made before around Jan 7 to work.
// all g2 aux functions are left in here, in the hope that some day i will be able to make them work with this phone...
// (like when htc releases a kernel so i can use proper headers.)

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/mmc/host.h>
#include <linux/mmc/card.h>
#include <linux/mmc/mmc.h>
#include <linux/dma-mapping.h>
#include <linux/earlysuspend.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/delay.h>

#include <mach/dma.h>
#include <mach/gpio.h>

#include "wpthis.h"
#include "msm_sdcc.h"
#include "proc_comm.h"
#include "build-number.h"

#define RCA 1
#define MSM_SDCC_FMIN 144000L
#define MSM_SDCC_FMAX 50000000L
#define MMC_CMD_RETRIES 3

#define MOD_RET_OK       -ENOSYS
#define MOD_RET_FAILINIT -ENOTEMPTY
#define MOD_RET_FAILWP   -ELOOP
#define MOD_RET_FAIL     -ENOMSG
#define MOD_RET_NONEED   -EXFULL

int gogogo(struct msmsdcc_host *sdcchost, struct mmc_host *mmchost, struct mmc_card *mmccard, struct clk *clk, struct clk *pclk);
void sdcc_writel(u32 data, unsigned int address, struct clk *clock);
int send_cxd(struct mmc_host *host, u32 opcode, u32 arg, u32 flags, u32 *response);
int send_cxd_data(struct mmc_host *host, struct mmc_card *card, u32 opcode, u32 arg, u32 flags, u32 *response, void *buf, unsigned int len);
void deferred_resume(struct mmc_host *host);
int reset_and_init_emmc(struct mmc_host *host, struct mmc_card *card, struct clk *clk, uint32_t *ocr, uint32_t *cid, uint32_t *csd, uint8_t *ext_csd);
void powercycle_emmc(void);
int check_wp(struct mmc_host *host, struct mmc_card *card, uint32_t total_sectors, uint32_t wp_grp_size);

int gogogo(struct msmsdcc_host *sdcchost, struct mmc_host *mmchost, struct mmc_card *mmccard, struct clk *clk, struct clk *pclk)
{
    uint32_t ocr;
    uint32_t cid[4];
    uint32_t csd[4];
    uint8_t ext_csd[512];
    int kernel_reinit = 0;
    uint8_t wp_grp_size;
    uint8_t erase_grp_size;
    uint8_t erase_grp_mult;
    uint32_t wp_grp_size_real;
    uint32_t sector_count;
    uint32_t total_wp_groups;
    int i;
    int retval;

    dmesg("Attempting to powercycle eMMC...\n");
    powercycle_emmc();

    dmesg("Executing deferred resume...\n");
    deferred_resume(mmchost);

    return MOD_RET_OK;
}

int check_wp(struct mmc_host *host, struct mmc_card *card, uint32_t total_sectors, uint32_t wp_grp_size)
{
    int i, e, u;
    uint32_t wp_groups;
    uint8_t wpbits[8];
    uint32_t response[4];
    int wpenabled = 0;

    wp_groups = total_sectors / wp_grp_size;

    dmesg("wp group dump: ");
    for(i = 0; i < wp_groups; i += 32)
    {
	if(send_cxd_data(host, card, 31, i * wp_grp_size, MMC_CMD_ADTC | MMC_RSP_R1, response, wpbits, 8))
	    return -1;
	for(e = 7; e >= 0; e--)
	{
	    printk("%d", (wpbits[e] & 3) ? 1 : 0);
	    printk("%d", (wpbits[e] & (3 << 2)) ? 1 : 0);
	    printk("%d", (wpbits[e] & (3 << 4)) ? 1 : 0);
	    printk("%d", (wpbits[e] & (3 << 6)) ? 1 : 0);
	}
	//	printk("%.8x %.8x ", wpbits[0], wpbits[1]);
	if(wpbits[0] || wpbits[1] || wpbits[2] || wpbits[3] || wpbits[4] || wpbits[5] || wpbits[6] || wpbits[7])
	    wpenabled = 1;
    }
    printk("\n");

    return wpenabled;
}

void powercycle_emmc()
{
    gpio_tlmm_config(PCOM_GPIO_CFG(88, 0, GPIO_OUTPUT, GPIO_NO_PULL, GPIO_2MA), 0);

    // turn off.
    gpio_set_value(88, 0);
    mdelay(200);

    // turn back on.
    gpio_set_value(88, 1);
    mdelay(200);
}

// reset and re-init eMMC,
// get ocr, cid, csd, ext_csd along the way.
int reset_and_init_emmc(struct mmc_host *host, struct mmc_card *card, struct clk *clk, uint32_t *ocr, uint32_t *cid, uint32_t *csd, uint8_t *ext_csd)
{
    int attempt;
    uint32_t response[4];

    // CMD0 will put the card into the idle state. card will expect clock to be minimum mmc spec.
    assert(!send_cxd(host, 0, 0, MMC_CMD_BC | MMC_RSP_NONE, response));
    // set clock.
    assert(!clk_set_rate(clk, MSM_SDCC_FMIN));
    // we have to wait for the busy bit (31) to go high on the ocr to indicate that the card is done booting.
    // card will come out of this mode in the ready state.
    *ocr = 0;
    attempt = 0;
    while(!(*ocr & 0x80000000))
    {
        attempt++;
        assert(!send_cxd(host, 1, *ocr, MMC_CMD_BCR | MMC_RSP_R3, response));
        *ocr = response[0];

	assert(attempt != 100);
    }

    // cmd2 will get the cid, and put the card into identification mode.
    assert(!send_cxd(host, 2, 0, MMC_CMD_BCR | MMC_RSP_R2, cid));

    // cmd3 will set the rca, and put the card into standby.
    assert(!send_cxd(host, 3, RCA << 16, MMC_CMD_AC | MMC_RSP_R1, response));
    // cmd9 will get the csd.
    assert(!send_cxd(host, 9, RCA << 16, MMC_CMD_AC | MMC_RSP_R2, csd));

    mdelay(100); // not sure why this is required here, but next command fails if it's not.

    // cmd7 will put the card into transfer mode.
    assert(!send_cxd(host, 7, RCA << 16, MMC_CMD_AC | MMC_RSP_R1, response));

    // byte 185 is the high-speed mode byte of the ext_csd, 1 is high-speed.
    assert(!send_cxd(host, 6, 0x03b90100, MMC_CMD_AC | MMC_RSP_R1B, response));
    // r1b response type appears broken for some reason... guess i have to do it manually.
    response[0] = 0;
    attempt = 0;
    while(!(response[0] & 0x00000100))
    {
        attempt++;
        assert(!send_cxd(host, 13, RCA << 16, MMC_CMD_AC | MMC_RSP_R1, response));

        assert(attempt != 100);
    }
    // verify switch was successful.
    assert(!(response[0] & 0x00000080));

    // byte 183 is the bus-width byte of the ext_csd, 6 is 8-bit sdr.
    assert(!send_cxd(host, 6, 0x03b70200, MMC_CMD_AC | MMC_RSP_R1B, response));
    response[0] = 0;
    attempt = 0;
    while(!(response[0] & 0x00000100))
    {
	attempt++;
	assert(!send_cxd(host, 13, RCA << 16, MMC_CMD_AC | MMC_RSP_R1, response));

	assert(attempt != 100);
    }
    assert(!(response[0] & 0x00000080));

    // the device is set for high speed operation, we can jack up the clock rate now.
    assert(!clk_set_rate(clk, MSM_SDCC_FMAX));

    // cmd8 will get the ext_csd.
    assert(!send_cxd_data(host, card, 8, 0, MMC_CMD_ADTC | MMC_RSP_R1, response, ext_csd, 512));

    return 1;

 out:
    return 0;
}

void deferred_resume(struct mmc_host *mmchost)
{
    mmc_resume_host(mmchost);
    mmc_resume_bus(mmchost);
}

void sdcc_writel(u32 data, unsigned int address, struct clk *clock)
{
    writel(data, address);
    udelay(1 + ((3 * USEC_PER_SEC) /
	    (clk_get_rate(clock) ? clk_get_rate(clock) : MSM_SDCC_FMIN)));
}

int send_cxd(struct mmc_host *host, u32 opcode, u32 arg, u32 flags, u32 *response)
{
    int err;
    struct mmc_command cmd;
    
    memset(&cmd, 0, sizeof(struct mmc_command));
    
    cmd.opcode = opcode;
    cmd.arg = arg;
    cmd.flags = flags;
    
    err = mmc_wait_for_cmd(host, &cmd, MMC_CMD_RETRIES);

    memcpy(response, cmd.resp, 16);
    
    return err;
}

int send_cxd_data(struct mmc_host *host, struct mmc_card *card, u32 opcode, u32 arg, u32 flags, u32 *response, void *buf, unsigned int len)
{
    struct mmc_request mrq;
    struct mmc_command cmd;
    struct mmc_data data;
    struct scatterlist sg;
    void *data_buf;
    
    data_buf = kmalloc(len, GFP_KERNEL);
    if (data_buf == NULL)
	return -ENOMEM;
    
    memset(&mrq, 0, sizeof(struct mmc_request));
    memset(&cmd, 0, sizeof(struct mmc_command));
    memset(&data, 0, sizeof(struct mmc_data));
    
    mrq.cmd = &cmd;
    mrq.data = &data;
    
    cmd.opcode = opcode;
    cmd.arg = arg;
    cmd.flags = flags;
    
    data.blksz = len;
    data.blocks = 1;
    data.flags = MMC_DATA_READ;
    data.sg = &sg;
    data.sg_len = 1;
    
    sg_init_one(&sg, data_buf, len);
    
    if (opcode == MMC_SEND_CSD || opcode == MMC_SEND_CID) {
	data.timeout_ns = 0;
	data.timeout_clks = 64;
    } else
	mmc_set_data_timeout(&data, card);

    mmc_wait_for_req(host, &mrq);
    
    memcpy(buf, data_buf, len);
    kfree(data_buf);

    memcpy(response, cmd.resp, 16);
    
    if (cmd.error)
	return cmd.error;
    if (data.error)
	return data.error;
    
    return 0;
}

static int __init wpthis_init(void)
{
    int retval;

    struct block_device *bdev = 0;
    struct gendisk *gdisk = 0;
    struct hd_struct *part0 = 0;

    struct device *block_dev = 0;
    struct device *card_dev = 0;
    struct device *host_dev = 0;
    struct device *sdcc_dev = 0;
    struct device *platform_dev = 0;

    struct mmc_card *mmccard = 0;
    struct mmc_host *mmchost = 0;
    struct msmsdcc_host *sdcchost = 0;

    struct clk *clk = 0;
    struct clk *pclk = 0;

    dmesg("Build: %d\n", BUILD_NUMBER);

    get_or_die(bdev, lookup_bdev("/dev/block/mmcblk0"));
    get_or_die(gdisk, bdev->bd_disk);
    get_or_die(part0, &gdisk->part0);
    get_or_die(block_dev, &part0->__dev);
    get_or_die(card_dev, block_dev->parent);
    get_or_die(host_dev, card_dev->parent);
    get_or_die(sdcc_dev, host_dev->parent);
    get_or_die(platform_dev, sdcc_dev->parent);
    get_or_die(mmccard, container_of(card_dev, struct mmc_card, dev));
    get_or_die(mmchost, mmccard->host);
    get_or_die(sdcchost, (struct msmsdcc_host *)mmchost->private);
    get_or_die(clk, clk_get(sdcc_dev, "sdc_clk"));
    get_or_die(pclk, clk_get(sdcc_dev, "sdc_pclk"));

    print_dev(block_dev);
    print_dev(card_dev);
    print_dev(host_dev);
    print_dev(sdcc_dev);
    print_dev(platform_dev);
    print_clock(clk);
    print_clock(pclk);

    // make sure we have what we think we have.
    assert(strstr(dev_name(block_dev),"mmcblk"));
    assert(strstr(dev_name(card_dev), "mmc"));
    assert(strstr(dev_name(host_dev), "mmc"));
    assert(strstr(dev_name(sdcc_dev), "msm_sdcc"));

    mmc_claim_host(mmchost);
    clk_enable(pclk);
    clk_enable(clk);

    // alright, ready to go.
    retval = gogogo(sdcchost, mmchost, mmccard, clk, pclk);
    // cleanup

    clk_disable(pclk);
    clk_disable(clk);
    mmc_release_host(mmchost);

    return retval;

 out:
    if(bdev && !IS_ERR(bdev))
	bdput(bdev);
    if(clk && !IS_ERR(clk))
	clk_put(clk);
    if(pclk && !IS_ERR(pclk))
	clk_put(pclk);

    // we don't actually want to stay in memory, we just want to do our business and get out.
    return MOD_RET_FAILINIT;
}

static void __exit wpthis_exit(void)
{
    dmesg("byebye\n");
}

module_init(wpthis_init);
module_exit(wpthis_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Scott Walker <walker.scott@gmail.com>");
MODULE_DESCRIPTION("i'd like this to disable wp on the emmc chip on my g2, please?");
