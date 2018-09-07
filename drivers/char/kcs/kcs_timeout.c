/*
 ****************************************************************
 **                                                            **
 **    (C)Copyright 2006-2009, American Megatrends Inc.        **
 **                                                            **
 **            All Rights Reserved.                            **
 **                                                            **
 **        5555 Oakbrook Pkwy Suite 200, Norcross,             **
 **                                                            **
 **        Georgia - 30093, USA. Phone-(770)-246-8600.         **
 **                                                            **
 ****************************************************************
 */

#include <linux/module.h>
#include <linux/kernel.h>
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/kernel.h>
#include <linux/ide.h>

#include <char/kcs/kcs_timeout.h>


void Kcs_OsInitSleepStruct(Kcs_OsSleepStruct *Sleep);
void Kcs_OsWakeupOnTimeout(Kcs_OsSleepStruct *Sleep);
long Kcs_OsSleepOnTimeout(Kcs_OsSleepStruct *Sleep,u8 *Var,long msecs);
void SleepTimeOut(unsigned long SleepPtr);



void 
Kcs_OsInitSleepStruct(Kcs_OsSleepStruct *Sleep)
{
	init_waitqueue_head(&(Sleep->queue));
	init_timer(&(Sleep->tim));
	Sleep->Timeout = 0;
	return;
}


void 
Kcs_OsWakeupOnTimeout(Kcs_OsSleepStruct *Sleep)
{
	int dtimer;

	/* Wakeup Process and Kill timeout handler */
	dtimer=del_timer(&(Sleep->tim));
	wake_up(&(Sleep->queue));

	if (Sleep->Timeout)
		printk("WARNING:Wakeup for Sleep Struct Called after timeout\n");
	return;
}


long 
Kcs_OsSleepOnTimeout(Kcs_OsSleepStruct *Sleep,u8 *Var,long msecs)
{
	long timeout;	/* In jiffies */
	int  dtimer;
	u8 *volatile Condition = Var;

	/* Convert milliseconds into jiffies*/
	timeout = (HZ*msecs)/1000;

	/* Start the timeout */
	Sleep->tim.function = SleepTimeOut;
	Sleep->tim.data     = (unsigned long)Sleep;
	Sleep->tim.expires  = jiffies+timeout;
	Sleep->Timeout      = 0;
	if (msecs)
		add_timer(&(Sleep->tim));

	//#if DEBUG_ARCH
	//printk("Sleeping on Sleep Structure\n");
	//#endif

	/* Sleep on the Condition for a wakeup */
	wait_event_interruptible(Sleep->queue,((*Condition)||(Sleep->Timeout)));

	/* Normally del_timer will be called by Wakeup or timeout routine */
	/* But when wakeup is called before add_timer() and wait_event(),
	   it will not be killed by wakeup routine and will be killed only
	   after a timeout happens. So we kill it here as soon as possible */
	if (msecs)
		dtimer = del_timer(&(Sleep->tim));

	if (Sleep->Timeout)
		return 0;
	return timeout;
}

void 
SleepTimeOut(unsigned long SleepPtr)
{	
	Kcs_OsSleepStruct *Sleep;

	/* Set Timeout and Wakeup Sleep Process */
	Sleep = (Kcs_OsSleepStruct *)SleepPtr;
	Sleep->Timeout = 1;
	wake_up(&(Sleep->queue));

	return;
}



