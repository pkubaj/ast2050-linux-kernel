/*
 * KCS Common Driver
 *
 * (C) Copyright 2017 Raptor Engineering, LLC
 * (C) Copyright 2006-2009, American Megatrends Inc.
 *
 * Author : Timothy Pearson <tpearson@raptorengineering.com>
 *          Jothiram Selvam <jothirams@ami.com>
 *          Vinay Tandon <vinayt@ami.com>
 * This driver provides common layer, independent of the hardware, for the KCS driver.
 */

// #define DEBUG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include <char/kcs/kcs.h>
#include <char/kcs/kcsifc.h>
#include <char/kcs/kcs_ioctl.h>

#ifdef DEBUG
#define dbgprint(fmt, args...)       printk (KERN_INFO fmt, ##args) 
#else
#define dbgprint(fmt, args...)       
#endif

#define KCS_MAJOR           42
#define KCS_MINOR	    0
#define KCS_MAX_CHANNELS    255
#define KCS_DEV_NAME        "kcs"


#define IS_IBF_SET(STATUS)     (0 != ((STATUS) & 0x02))
#define IS_WRITE_TO_CMD_REG(STATUS)    (0 != ((STATUS) & 0x08))
#define CHK_STATE_IDLE(STATUS)     (0 == ((STATUS) & 0xC0))

unsigned int m_kcs_ch_count = 0;
int m_dev_id = 1;

struct kcs_dev
{
	KCSBuf_T *pkcs_buf;
	IPMICmdMsg_T* pipmi_cmd_msg;
	kcs_driver_operations_t *driver_ops;
	unsigned char ch_num;
};

/* Sysctl Table */
static struct ctl_table KCS_table [] =
{
        {0}
};

/* Proc and Sysctl entries */
static kcs_driver_operations_t *dev_ops = NULL;
static unsigned char channel_number = 0;
static struct proc_dir_entry *moduledir = NULL;
static struct ctl_table_header *my_sys  = NULL;
static struct proc_dir_entry *proc_root_dir = NULL;

/*-----------------------------------------------*
 **         Prototype Declaration       **
 *-----------------------------------------------*/

EXPORT_SYMBOL(kcs_init);
EXPORT_SYMBOL(kcs_exit);
EXPORT_SYMBOL(process_kcs_intr);

static int kcs_open (struct inode *inode, struct file *filp);
static int kcs_release (struct inode *inode, struct file *filp);
static int kcs_ioctl (struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);
static ssize_t kcs_read (struct file *filp, char __user *buf, size_t count, loff_t *offset);
static ssize_t kcs_write (struct file *filp, const char __user *buf, size_t count, loff_t *offset);

static int kcs_clear_sms_bit (struct kcs_dev *pdev, unsigned long arg);
static int kcs_set_sms_bit (struct kcs_dev *pdev, unsigned long arg);
static int kcs_set_obf_bit (struct kcs_dev *pdev, unsigned long arg);
static int kcs_hw_unit_test (struct kcs_dev *pdev, unsigned long arg);
static int read_kcs_data (struct kcs_dev *pdev, unsigned long arg);
static int write_kcs_data (struct kcs_dev *pdev, unsigned long arg);
static int write_kcs_status_data (struct kcs_dev *pdev, unsigned long arg);

static int kcs_request (struct kcs_dev *pdev, char *pbuf);
static size_t kcs_write_request (struct kcs_dev *pdev, const char* buf, size_t count);
static void send_kcs_response (struct kcs_dev *pdev);
static void kcs_recv_byte (struct kcs_dev *pdev, unsigned char ch_num);

static void set_kcs_state (struct kcs_dev *pdev, unsigned char ch_num, u8 state_value);
static void set_obf_status (struct kcs_dev *pdev, unsigned char ch_num);


extern unsigned int m_kcs_hw_test_enable;

extern void Kcs_OsInitSleepStruct(Kcs_OsSleepStruct *Sleep);
extern void Kcs_OsWakeupOnTimeout(Kcs_OsSleepStruct *Sleep);
extern long Kcs_OsSleepOnTimeout(Kcs_OsSleepStruct *Sleep,u8 *Var,long msecs);
extern void SleepTimeOut(unsigned long SleepPtr);
void read_kcs_status(u8 ch_num, u8* status_value);
void write_kcs_status(u8 ch_num, u8 status_value);

static struct file_operations kcs_fops = {
        owner:      THIS_MODULE,
        read:       kcs_read,
        write:      kcs_write,
        ioctl:      kcs_ioctl,
        open:       kcs_open,
        release:    kcs_release,
};

static struct cdev *kcs_cdev;
static dev_t kcs_devno = MKDEV(KCS_MAJOR, KCS_MINOR);
static char banner[] __initdata = KERN_INFO "KCS Common Driver, (c) 2009 American Megatrends Inc.\n";	

static struct kcs_dev *default_pdev = NULL;

/***********************************************************************************************/

static struct ctl_table_header *
AddSysctlTable(char *ModuleName,struct ctl_table* ModuleTable)
{
	struct ctl_table *root_table;
	struct ctl_table *module_root_table;
	struct ctl_table_header *table_header;

	/* Create the root directory under /proc/sys*/
	root_table = kmalloc(sizeof(ctl_table)*2,GFP_KERNEL);
	if (!root_table)
		return NULL;

	/* Create the module directory under /proc/sys/ractrends*/
	module_root_table = kmalloc(sizeof(ctl_table)*2,GFP_KERNEL);
	if (!module_root_table)
	{
		kfree(root_table);
		return NULL;
	}
	
	/* Fill up root table */	
	memset(root_table,0,sizeof(ctl_table)*2);
	root_table[1].ctl_name  = 0;			/* Terminate Structure */
#if (LINUX_VERSION_CODE >=  KERNEL_VERSION(2,6,24))
	root_table[0].ctl_name	= CTL_UNNUMBERED;
#else
	root_table[0].ctl_name  = 5000;
#endif
	root_table[0].procname  = KCS_PROC_ROOT_DIR;
	root_table[0].data		= NULL;
	root_table[0].maxlen 	= 0;
	root_table[0].mode		= 0555;		/* _r_xr_xr_x */
	root_table[0].child 	= module_root_table;

	/* Fill up the module root table */
	memset(module_root_table,0,sizeof(ctl_table)*2);
	module_root_table[1].ctl_name = 0;	  /* Terminate Structure */	
#if (LINUX_VERSION_CODE >=  KERNEL_VERSION(2,6,24))
	module_root_table[0].ctl_name = CTL_UNNUMBERED;		/* What happens when another module registers */
#else
	module_root_table[0].ctl_name = 1;
#endif
	module_root_table[0].procname = ModuleName;
	module_root_table[0].data		= NULL;
	module_root_table[0].maxlen 	= 0;
	module_root_table[0].mode		= 0555;		/* _r_xr_xr_x */
	module_root_table[0].child 	= ModuleTable;

#if (LINUX_VERSION_CODE >=  KERNEL_VERSION(2,6,24))
	table_header = register_sysctl_table(root_table);
#else
	table_header = register_sysctl_table(root_table, 1);
#endif
	
	return table_header;
}

static void
RemoveSysctlTable(struct ctl_table_header *table_header)
{
	struct ctl_table *root_table;

	if (!table_header)
		return;
			
	/* Hack: Get the root_table from table_header : Refer sysctl.c */
	root_table = table_header->ctl_table;
		
	/* unregister the sysctl table from kernel */		
	unregister_sysctl_table(table_header);

	if (!root_table)		
		return;
	
	/* free module root table */
	if (root_table->child)
			kfree(root_table->child);

	/* free the root table */
	kfree(root_table);
	return;
}

void kcs_exit(void)
{
	dev_ops = NULL;

	unregister_chrdev_region (kcs_devno, KCS_MAX_CHANNELS);

	if (NULL != kcs_cdev)
	{
		dbgprint ("kcs char device del\n");
		cdev_del (kcs_cdev);
	}
	RemoveSysctlTable(my_sys);
	remove_proc_entry("kcs", proc_root_dir);
	printk("KCS Common module unloaded successfully\n");
	return;
}

static int
kcs_open(struct inode *inode, struct file *file)
{
	unsigned int minor = iminor(inode);
	struct kcs_dev* pdev;
	KCSBuf_T* pKCSBuffer;

	pdev = (struct kcs_dev*) kmalloc (sizeof(struct kcs_dev), GFP_KERNEL);

	if (!pdev)
	{
		printk (KERN_ERR "%s: failed to allocate kcs private dev structure for kcs iminor: %d\n", KCS_DEV_NAME, minor);
		return -ENOMEM;
	}

	pdev->pkcs_buf = (KCSBuf_T*) kmalloc (sizeof(KCSBuf_T), GFP_KERNEL);
	if (!pdev->pkcs_buf)
	{
		kfree (pdev);
		printk (KERN_ERR "%s: failed to allocate kcs pkcs buffer structure for kcs iminor: %d\n", KCS_DEV_NAME, minor);
		return -ENOMEM;
	}

	pdev->pipmi_cmd_msg = (IPMICmdMsg_T*) vmalloc (sizeof(IPMICmdMsg_T));
	if (!pdev->pipmi_cmd_msg)
	{
		kfree (pdev);
		kfree (pdev->pkcs_buf);
		printk (KERN_ERR "%s: failed to allocate kcs ipmi command buffer structure for kcs iminor: %d\n", KCS_DEV_NAME, minor);
		return -ENOMEM;
	}

	dbgprint ("kcs_buf addr : %p\n", &pdev->pkcs_buf);
	pdev->pkcs_buf->pKCSRcvPkt = pdev->pipmi_cmd_msg->Request;
	pdev->pkcs_buf->KcsWakeup = 0;
	pdev->pkcs_buf->TxReady = 0;
	pdev->pkcs_buf->KcsIFActive = 0;
	pdev->pkcs_buf->KcsWtIFActive = 0;
	pdev->pkcs_buf->FirstTime = 1;
	pdev->pkcs_buf->KcsResFirstTime = 1;
	pdev->pkcs_buf->KcsINuse = 0;
	pdev->pkcs_buf->PrevCmdAborted = 0;

	pdev->driver_ops = dev_ops;

	pKCSBuffer = pdev->pkcs_buf;
	dbgprint ("%d, kcs_open bufffer addr : %p\n", minor, pKCSBuffer);
	pKCSBuffer->KCSRcvPktIx = 0;
	pKCSBuffer->KCSSendPktIx = 0;
	pKCSBuffer->KCSSendPktLen = 0;
	pKCSBuffer->KCSPhase = KCS_PHASE_IDLE;
	pKCSBuffer->KcsINuse = 1;
	pdev->ch_num = channel_number;
	dbgprint ("%d, kcs_open ch num : %d\n", minor, pdev->ch_num);
	file->private_data = pdev;
	default_pdev = pdev;

	pdev->driver_ops->kcs_interrupt_enable_user();

	dbgprint ("%d, kcs_open priv data addr : %p\n", minor, &file->private_data);	
	return nonseekable_open (inode, file);
}

static int 
kcs_release (struct inode *inode, struct file *file)
{
	struct kcs_dev *pdev = (struct kcs_dev*) file->private_data;
#ifdef DEBUG
	KCSBuf_T *pKCSBuffer = pdev->pkcs_buf;
#endif

	pdev->driver_ops->kcs_interrupt_disable_user();

	dbgprint ("%d, ch: %d kcs_release priv data addr : %p\n", iminor(inode), pdev->ch_num, pdev);
	dbgprint ("%d, kcs_release kcs_buf addr : %p\n", iminor(inode), pKCSBuffer);
	vfree (pdev->pipmi_cmd_msg);
	kfree (pdev->pkcs_buf);
	kfree (pdev);
	default_pdev = NULL;
	return 0;
}

static int 
kcs_ioctl (struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct kcs_dev *pdev = (struct kcs_dev*) file->private_data;

	switch(cmd)
	{
		case SET_SMS_BIT:
			ret = kcs_set_sms_bit (pdev, arg);
			break;
		case CLEAR_SMS_BIT:
			ret = kcs_clear_sms_bit (pdev, arg);
			break;
		case ENABLE_KCS_INTERRUPT:
			pdev->driver_ops->enable_kcs_interrupt();
		case DISABLE_KCS_INTERRUPT:
			pdev->driver_ops->disable_kcs_interrupt();
			break;
		case START_HW_UNIT_TEST:
			ret = kcs_hw_unit_test ( pdev, arg );
		case READ_KCS_DATA:
			ret = read_kcs_data ( pdev, arg );
			break;
		case WRITE_KCS_DATA:
			ret = write_kcs_data ( pdev, arg );
			break;		
		case SET_OBF_BIT:
			ret = kcs_set_obf_bit (pdev, arg);	
			break;
		case KCS_ENABLE:
			pdev->driver_ops->kcs_interrupt_enable_user();
			break;
		case KCS_DISABLE:
			pdev->driver_ops->kcs_interrupt_disable_user();
			break;
		case SET_STATUS_DATA:	
			ret=write_kcs_status_data(pdev, arg);
			break;			
		default:
			dbgprint ("invalid ioctl command in <%s> char device\n", KCS_DEV_NAME);
			break;
	}
	return ret;
}

int 
kcs_set_sms_bit (struct kcs_dev *pdev, unsigned long arg)
{
	u8 status = 0;
	kcs_data_t kcs_data;

	if (copy_from_user (&kcs_data, (void*)arg, sizeof(kcs_data_t)))
		return -EFAULT;

	pdev->driver_ops->read_kcs_status (kcs_data.kcsifcnum, &status);

	if (IS_IBF_SET(status))
		kcs_recv_byte (pdev, 1);
	status = status | 0x04;
	pdev->driver_ops->write_kcs_status (kcs_data.kcsifcnum, status);

	return 0;
}

int 
kcs_clear_sms_bit (struct kcs_dev *pdev, unsigned long arg)
{
	u8 status = 0;
	kcs_data_t kcs_data;

	if ( copy_from_user(&kcs_data, (void*)arg, sizeof(kcs_data_t)) )
		return -EFAULT;

	pdev->driver_ops->read_kcs_status (kcs_data.kcsifcnum, &status);

	if (IS_IBF_SET(status))
		kcs_recv_byte (pdev, 1);
	status = status & ~0x04;
	pdev->driver_ops->write_kcs_status (kcs_data.kcsifcnum, status);
	
	return 0;
}
int 
kcs_set_obf_bit (struct kcs_dev *pdev, unsigned long arg)
{
	u8 status = 0;
	kcs_data_t kcs_data;

	if ( copy_from_user(&kcs_data, (void*)arg, sizeof(kcs_data_t)) )
		return -EFAULT;
	
	pdev->driver_ops->read_kcs_status (kcs_data.kcsifcnum, &status);
	
	if (CHK_STATE_IDLE(status))
	{
		pdev->driver_ops->write_kcs_data_out(kcs_data.kcsifcnum, status);
	}
	
	return 0;
}

int
kcs_hw_unit_test (struct kcs_dev *pdev, unsigned long arg)
{
	u8 data_packet;
	u8 status_reg;
	int i = 0;
	unsigned int channel_num;

	pdev->driver_ops->disable_kcs_interrupt();
	channel_num = (unsigned int) arg; 
	pdev->driver_ops->read_kcs_status(channel_num, &status_reg);

	for (i=0; i<10; i++)
	{
		printk("\tTest Run %d\n", i);
		pdev->driver_ops->read_kcs_status(channel_num, &status_reg);
		while (0 == (status_reg & 0x02))
		{
			schedule_timeout_interruptible ( 100 );
			pdev->driver_ops->read_kcs_status(channel_num, &status_reg);
		}
		pdev->driver_ops->read_kcs_data_in (channel_num, &data_packet);
		printk("\t\tHost Data = %d\n", data_packet);
		pdev->driver_ops->write_kcs_data_out (channel_num, data_packet);

		pdev->driver_ops->read_kcs_status(channel_num, &status_reg);
		if ( 0 != (status_reg & 0x02))
			pdev->driver_ops->write_kcs_status(channel_num, (status_reg | (0x02)));
		schedule_timeout_interruptible ( 100 );
	}

	pdev->driver_ops->enable_kcs_interrupt();
	return 0;
}


int
read_kcs_data (struct kcs_dev *pdev, unsigned long arg)
{
	unsigned char status_reg;
	struct kcs_data_t kdata;
	int i = 0;

	if  (copy_from_user (&kdata, (void*) arg, sizeof(struct kcs_data_t)))
		return -EFAULT;
	for (i=0; i < kdata.num_bytes; i++)
	{
		pdev->driver_ops->read_kcs_status (kdata.channel_num, &status_reg);
		while ( 0 == (status_reg & 0x02) )
		{
			schedule_timeout_interruptible ( 100 );
			pdev->driver_ops->read_kcs_status (kdata.channel_num, &status_reg);
		}
		pdev->driver_ops->read_kcs_data_in (kdata.channel_num, &(kdata.buffer[i]));
		
		pdev->driver_ops->read_kcs_status (kdata.channel_num, &status_reg);
		if (status_reg & 0x02)
			pdev->driver_ops->write_kcs_status (kdata.channel_num, status_reg | 0x02 );
			
	}
	if  (copy_to_user ((void*) arg, &kdata, sizeof(struct kcs_data_t)))
		return -EFAULT;
	return 0;
}

int
write_kcs_data (struct kcs_dev *pdev, unsigned long arg)
{
	unsigned char status_reg;
	struct kcs_data_t kdata;
	int i = 0;

	if  (copy_from_user (&kdata, (void*) arg, sizeof(struct kcs_data_t)))
		return -EFAULT;
	for (i=0; i < kdata.num_bytes; i++)
	{
		pdev->driver_ops->write_kcs_data_out (kdata.channel_num, kdata.buffer[i]);
		pdev->driver_ops->read_kcs_status (kdata.channel_num, &status_reg);
		while ( 0 == (status_reg & 0x01) )
		{
			schedule_timeout_interruptible ( 100 );
			pdev->driver_ops->read_kcs_status (kdata.channel_num, &status_reg);
		}
	}
	return 0;
}

int
write_kcs_status_data (struct kcs_dev *pdev, unsigned long arg)
{	
	u8  status_reg = 0;
	struct kcs_status_data_t kstatusdata;

	if  (copy_from_user (&kstatusdata, (void*) arg, sizeof(struct kcs_status_data_t)))
		return -EFAULT;
	pdev->driver_ops->read_kcs_status (kstatusdata.channel_num, &status_reg);
	status_reg = status_reg & 0x3F;
	kstatusdata.status = kstatusdata.status << 6;
	status_reg = status_reg | kstatusdata.status;
	pdev->driver_ops->write_kcs_status (kstatusdata.channel_num, status_reg);
	
	return 0;
}

static ssize_t
kcs_read (struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct kcs_dev *pdev = (struct kcs_dev*) file->private_data;
	dbgprint ("kcs_read: ch num: %d, priv data addr : %p\n", pdev->ch_num, file->private_data);
	return kcs_request (pdev, buf);
}

int 
kcs_request (struct kcs_dev *pdev, char *pbuf)
{
	KCSBuf_T *pKCSBuffer = pdev->pkcs_buf;

	dbgprint ("kcs_request ch num: %d, kcs_buf addr : %p\n", pdev->ch_num, pKCSBuffer);

	/* Initialize Sleep Structure for the First Time */
	if (pKCSBuffer->FirstTime)
	{
		Kcs_OsInitSleepStruct(&(pKCSBuffer->KcsReqWait));
		pKCSBuffer->FirstTime = 0;
	}

	dbgprint ("sleeping in kcs_request for ch num: %d\n", pdev->ch_num);
	pKCSBuffer->KcsIFActive     = 1;
	Kcs_OsSleepOnTimeout(&(pKCSBuffer->KcsReqWait),&(pKCSBuffer->KcsWakeup),0);
	pKCSBuffer->KcsWakeup       = 0;
	pKCSBuffer->KcsIFActive     = 0;

	dbgprint ("out of sleep in kcs_request for ch num: %d\n", pdev->ch_num);

	if (__copy_to_user( (void *)pbuf, (void *)pKCSBuffer->pKCSRcvPkt,  pKCSBuffer->KCSRcvPktIx ))
		return -EFAULT;
	return pKCSBuffer->KCSRcvPktIx;
}

static ssize_t
kcs_write (struct file *file, const char *buf, size_t count, loff_t *offset)
{
	struct kcs_dev *pdev = (struct kcs_dev*) file->private_data;	
	dbgprint ("kcs_write: ch num: %d, priv data addr : %p\n", pdev->ch_num, file->private_data);
	return kcs_write_request (pdev, buf, count);
}

size_t 
kcs_write_request (struct kcs_dev *pdev, const char* buf, size_t count)
{
	IPMICmdMsg_T *pKCSCmdMsg = pdev->pipmi_cmd_msg;	
	KCSBuf_T *pKCSBuffer = pdev->pkcs_buf;

	dbgprint ("kcs_write_request ch num: %d, kcs_buf addr : %p\n", pdev->ch_num, pKCSBuffer);

	/* Copy from user data area to kernel data area*/
	if (__copy_from_user((void *)(pKCSCmdMsg->Response),(void *)buf,count))
		return -EFAULT;

	pKCSCmdMsg->ResponseSize = count;

	/* Send the response to KCS Channel */
	send_kcs_response (pdev);

	/* Initialize Sleep Structure for the First Time */
	if (pKCSBuffer->KcsResFirstTime)
	{
		Kcs_OsInitSleepStruct(&(pKCSBuffer->KcsResWait));
		pKCSBuffer->KcsResFirstTime = 0;
	}

	pKCSBuffer->KcsWtIFActive = 1;
	pKCSBuffer->TxReady       = 0;
	pKCSBuffer->KcsWtIFActive = 0;
	return count;
}

/**
 * @brief Prepare KCS buffer and send it on given channel.
 * @param ChannelNum - KCS channel number.
 * @param MsgPkt     - Response message packet.
 **/
void 
send_kcs_response (struct kcs_dev *pdev)
{
	IPMICmdMsg_T *pKCSCmdMsg = pdev->pipmi_cmd_msg;
	KCSBuf_T *pKCSBuffer = pdev->pkcs_buf;

	dbgprint ("send_kcs_response ch num: %d, kcs_buf addr : %p pKCSBuffer->PrevCmdAborted: %d\n", pdev->ch_num, pKCSBuffer, pKCSBuffer->PrevCmdAborted);
	
	/* If we are responding to an aborted request skip sending data */ 
	if (pKCSBuffer->PrevCmdAborted)
	{
		pKCSBuffer->PrevCmdAborted = 0; 
		return;
	} 
	/* Update the send buffer and associated indexes */
	pKCSBuffer->pKCSSendPkt = pKCSCmdMsg->Response;
	pKCSBuffer->KCSSendPktLen = pKCSCmdMsg->ResponseSize;
	pKCSBuffer->KCSSendPktIx = 0;

	/* Send the first byte */
	pKCSBuffer->KCSSendPktIx++;
	pdev->driver_ops->write_kcs_data_out (pdev->ch_num, pKCSBuffer->pKCSSendPkt[0]);
	//SA Set OBF Byte
	set_obf_status (pdev, pdev->ch_num);

	/* From now onwards the data is sent from the IBF Interrupt handler */
	return;
}

static void 
set_kcs_state (struct kcs_dev *pdev, unsigned char ch_num, u8 state_value)
{
        u8 status_val = 0;
        pdev->driver_ops->read_kcs_status (ch_num, &status_val);
        status_val = ((status_val & (~0xC0)) | (state_value));
        pdev->driver_ops->write_kcs_status (ch_num, status_val);
}

static void 
set_obf_status (struct kcs_dev *pdev, unsigned char ch_num)
{
        u8 status_val = 0;
        pdev->driver_ops->read_kcs_status (ch_num, &status_val);
        status_val = status_val | 0x01 ;
        pdev->driver_ops->write_kcs_status (ch_num, status_val); 
}

int
process_kcs_intr (unsigned char ch_num)
{
	if (default_pdev) {
		dbgprint ("process_kcs_intr: ch_num:  %d, pdev is : %p\n", ch_num, default_pdev);
		kcs_recv_byte (default_pdev, ch_num);
		return 0;
	}
	else {
		return -ENXIO;
	}
}

void 
kcs_recv_byte (struct kcs_dev *pdev, unsigned char ch_num)
{
	u8      Status;
	u8          DummyByte=0;
	int         i;
	u8      Cmd;
	u8     b;
	KCSBuf_T *pKCSBuffer = pdev->pkcs_buf;
	dbgprint ("kcs_recv_byte: ch_num:  %d, kcs_buf is : %p\n", ch_num, pKCSBuffer);
	Status = 0; 

	/* Read the Present Status of KCS Port */
	pdev->driver_ops->read_kcs_status (ch_num, &Status);
	
	dbgprint ("KCS status reg = %x\n", Status);
	/* If write to command register */
	if (IS_WRITE_TO_CMD_REG(Status))
	{
		dbgprint ("WRITE_TO_CMD reg\n");
		Cmd = 0;

		/* Set the status to WRITE_STATE */
		set_kcs_state (pdev, ch_num, KCS_WRITE_STATE);
		/* Read the command */
		pdev->driver_ops->read_kcs_command (ch_num, &Cmd);

		switch (Cmd)
		{
			case KCS_WRITE_START :
				dbgprint ("KCS_WRITE_START\n");
				/* Set the Index to 0 */
				pKCSBuffer->KCSRcvPktIx = 0;
				/* Set the phase to WRITE */
				pKCSBuffer->KCSPhase = KCS_PHASE_WRITE;
				break;

			case KCS_WRITE_END :
				dbgprint ("KCS_WRITE_END\n");
				/* Set the phase to write end */
				pKCSBuffer->KCSPhase = KCS_PHASE_WRITE_END;
				break;

			case KCS_ABORT : 
				dbgprint ("KCS_ABORT\n");
				if (!pKCSBuffer->KcsIFActive) 
				{ 
					/* Set flag to avoid sending response*/ 
					pKCSBuffer->PrevCmdAborted = 1; 
				} 
				/* Set the error code */
				if (KCS_NO_ERROR == pKCSBuffer->KCSError)
				{
					pKCSBuffer->KCSError = KCS_ABORTED_BY_COMMAND;
				}
				/* Set the phase to write end */
				pKCSBuffer->KCSPhase = KCS_PHASE_ABORT;
				/* Set the abort phase to be error1 */
				pKCSBuffer->AbortPhase = ABORT_PHASE_ERROR1;

				/* Send the dummy byte  */
				pdev->driver_ops->write_kcs_data_out (ch_num, 0);
				//SA Set OBF Byte
				set_obf_status (pdev, ch_num);
				break;

			default :
				dbgprint ("wrong value in CMD reg\n");
				/* Set the error code */
				pKCSBuffer->KCSError = KCS_ILLEGAL_CONTROL_CODE;
				/* Invalid command code - Set an error state */
				set_kcs_state (pdev, ch_num, KCS_ERROR_STATE);
				/* Set the phase to error phase */
				pKCSBuffer->KCSPhase = KCS_PHASE_ERROR;
				break;
		}
	}
	else
	{
		switch (pKCSBuffer->KCSPhase)
		{
			case KCS_PHASE_WRITE :
				dbgprint ("KCS_PHASE_WRITE\n");
				/* Set the state to write state */
				set_kcs_state (pdev, ch_num, KCS_WRITE_STATE);
				/* Read the BYTE from the data register */
				pdev->driver_ops->read_kcs_data_in (ch_num, &(pKCSBuffer->pKCSRcvPkt [pKCSBuffer->KCSRcvPktIx]));

				if (pKCSBuffer->KCSRcvPktIx < MAX_KCS_PKT_LEN)
				{
					pKCSBuffer->KCSRcvPktIx++;
				}
				break;

			case KCS_PHASE_WRITE_END :
				dbgprint ("KCS_PHASE_WRITE_END\n");
				/* Set the state to READ_STATE */
				set_kcs_state (pdev, ch_num, KCS_READ_STATE);

				/* Read the BYTE from the data register */
				pdev->driver_ops->read_kcs_data_in (ch_num, &(pKCSBuffer->pKCSRcvPkt [pKCSBuffer->KCSRcvPktIx]));

				pKCSBuffer->KCSRcvPktIx++;

				//SA lets print all data received from SMS

				dbgprint ("Total bytes received 0x%x\n", pKCSBuffer->KCSRcvPktIx );
				for(i=0;i < pKCSBuffer->KCSRcvPktIx ; i++)
				{
					dbgprint("0x%x ", pKCSBuffer->pKCSRcvPkt [i]);
				}
				dbgprint ("\npKCSBuffer->KcsIFActive:%x\n",pKCSBuffer->KcsIFActive);


				/* Signal receive data ready */
				/* Move to READ Phase */
				pKCSBuffer->KCSPhase = KCS_PHASE_READ;


				/* SA Wakeup KcsRequest to notify Request Packet is ready*/
				/* Wakeup only if KCS device is opened and is being used */
				if ( pKCSBuffer->KcsINuse)
					pKCSBuffer->KcsWakeup = 1;
				if (pKCSBuffer->KcsIFActive)
				{
					dbgprint ("Request received successfully\n");
					Kcs_OsWakeupOnTimeout(&(pKCSBuffer->KcsReqWait));
				}
				//else some error...
				break;

			case KCS_PHASE_READ :
				dbgprint ("KCS_PHASE_READ\n");
				/* If we have reached the end of the packet move to idle state */
				if (pKCSBuffer->KCSSendPktIx == pKCSBuffer->KCSSendPktLen)
				{
					set_kcs_state (pdev, ch_num, KCS_IDLE_STATE);
				}
				/* Read the byte returned by the SMS */
				{
					b = 0;
					pdev->driver_ops->read_kcs_data_in (ch_num, &b); 
					//SA Need to clear IBF
					//sa_0111 clear_IBF_status(ch_num);

					if (b != KCS_READ)
					{
						set_kcs_state (pdev, ch_num, KCS_ERROR_STATE);
						pdev->driver_ops->write_kcs_data_out (ch_num, 0);
						//SA Set OBF Byte
						set_obf_status (pdev, ch_num);
						break;
					}
				}
				/* If we are finished transmitting, send the dummy byte */
				if (pKCSBuffer->KCSSendPktIx == pKCSBuffer->KCSSendPktLen) 
				{
					pKCSBuffer->KCSPhase = KCS_PHASE_IDLE;
					pdev->driver_ops->write_kcs_data_out (ch_num, 0);
					//SA Set OBF Byte
					set_obf_status (pdev, ch_num);

					/* Set Transmission Complete */
					pKCSBuffer->TxReady     = 1;
					/* Wakeup Sleeping Process */
					//if(pKCSBuffer->KcsWtIFActive)
					//  Kcs_OsWakeupOnTimeout(&(pKCSBuffer->KcsResWait));
					break;
				}
				/* Transmit the next byte from the send buffer */
				pdev->driver_ops->write_kcs_data_out (ch_num, pKCSBuffer->pKCSSendPkt [pKCSBuffer->KCSSendPktIx]);
				//SA Set OBF Byte
				set_obf_status (pdev, ch_num);
				pKCSBuffer->KCSSendPktIx++;
				break;

			case KCS_PHASE_ABORT :
				dbgprint ("KCS_PHASE_ABORT\n");
				switch (pKCSBuffer->AbortPhase) 
				{
					case ABORT_PHASE_ERROR1 :
						/* Set the KCS State to READ_STATE */
						set_kcs_state (pdev, ch_num, KCS_READ_STATE);
						/* Read the Dummy byte  */
						pdev->driver_ops->read_kcs_data_in (ch_num, &DummyByte); 
						//SA Need to clear IBF
						//sa_0111 clear_IBF_status(ch_num);
						/* Write the error code to Data out register */
						pdev->driver_ops->write_kcs_data_out (ch_num, pKCSBuffer->KCSError);
						//SA Set OBF Byte
						set_obf_status (pdev, ch_num);
						/* Set the abort phase to be error2 */
						pKCSBuffer->AbortPhase = ABORT_PHASE_ERROR2;

						break;

					case ABORT_PHASE_ERROR2 :

						/**
						 * The system software has read the error code. Go to idle
						 * state.
						 **/
						set_kcs_state (pdev, ch_num, KCS_IDLE_STATE);

						/* Read the Dummy byte  */
						pdev->driver_ops->read_kcs_data_in (ch_num, &DummyByte); 

						pKCSBuffer->KCSPhase = KCS_PHASE_IDLE;
						pKCSBuffer->AbortPhase = 0;

						/* Send the dummy byte  */
						pdev->driver_ops->write_kcs_data_out (ch_num, 0);
						//SA Set OBF Byte
						set_obf_status (pdev, ch_num);

				}
				break;

			default:
				dbgprint ("incorrect Phase value\n");
				/* Read the Dummy byte  */
				pdev->driver_ops->read_kcs_data_in (ch_num, &DummyByte); 
				set_kcs_state (pdev, ch_num, KCS_ERROR_STATE);
				pdev->driver_ops->write_kcs_data_out (ch_num, 0);
				//SA Set OBF Byte
				set_obf_status (pdev, ch_num);
        }
    }
}

/* ----- Driver registration ---------------------------------------------- */

int kcs_init (kcs_driver_operations_t *devops, unsigned char ch_num, struct module* owner)
{
	int ret = 0;
	printk (banner);

	if ((ret = register_chrdev_region (kcs_devno, KCS_MAX_CHANNELS, KCS_DEV_NAME)) < 0)
	{
		printk (KERN_ERR "failed to register kcs device <%s> (err: %d)\n", KCS_DEV_NAME, ret);
		return ret;
	}

	kcs_cdev = cdev_alloc ();
	if (!kcs_cdev)
	{
		printk (KERN_ERR "%s: failed to allocate kcs cdev structure\n", KCS_DEV_NAME);
		unregister_chrdev_region (kcs_devno, KCS_MAX_CHANNELS);
		return -1;
	}

	cdev_init (kcs_cdev, &kcs_fops);
	kcs_cdev->owner = owner;

	if ((ret = cdev_add (kcs_cdev, kcs_devno, KCS_MAX_CHANNELS)) < 0)
	{
		printk  (KERN_ERR "failed to add <%s> char device\n", KCS_DEV_NAME);
		cdev_del (kcs_cdev);
		unregister_chrdev_region (kcs_devno, KCS_MAX_CHANNELS);
		ret = -ENODEV;
		return ret;	
	}

	dev_ops = devops;
	channel_number = ch_num;

	proc_root_dir = proc_mkdir(KCS_PROC_ROOT_DIR, NULL);
	moduledir = proc_mkdir("kcs", proc_root_dir);
	my_sys  = AddSysctlTable("kcs", &KCS_table[0]);
	return 0;
}


