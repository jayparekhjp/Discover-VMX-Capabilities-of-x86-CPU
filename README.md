# Discover-VMX-Capabilities-of-x86-CPU
This program can read MSRs (Model Specific Register) of the given machine we can determine whether different exit controls can be turned or or not for the given processor.

## Gist of Assignment: \n
This assignment focuses on finding different VMF features present in the processor by building and running a custom Linux Kernel module that queries different MSRs. The custom module will be a program written in C language and the output medium will be system logs.

## Prerequisites: \n
A machine having a processor that has VMX features exposed and is capable of running any one of distribution/flavor of Linux. A VM is better suited for the assignment as in case of a system failure/crash, the host machine won’t get affected.

## Environment Used: \n
Machine: Apple MacBook Pro 13”
Processor Type: Intel Core i7 (I7-8559U)
Processor Speed: 2.7 GHz
Host OS: macOS Mojave 10.14.3
Software Hypervisor: VMware Fusion
VMOS: Ubuntu 18.04.2 LTS

## Build Linux Kernel: \n
Check if git is installed or not. If not, then install:
		sudo apt-get install git
Clone the linux repository:
git clone https://github.com/torvalds/linux
Go into the linux repository and copy the OS boot config file into repository:
cd linux
cp /boot/config-4.18.0-15-generic .config
Install dependencies:
		sudo apt-get install libncurses-dev
		sudo apt-get install libssl-dev
Make kernel:
make menuconfig
make modules
make modules_install
make install

## Initial git commits: \n
Check and store the last git commit of the official repository to compare with the output and also to put the diff on.
		63bdf4284c38a48af21745ceb148a087b190cd21

## Create custom kernel module: \n
Create C language program cmpe283-1.c to discover processor’s MSRs and determine the VMX capabilities of the processor. File content is provided in the appendix of this file.
gedit cmpe283-1.c

---

Create Makefile to make the kernel module.
File Content: 
obj-m += cmpe283-1.o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	Run 
gedit Makefile
Run the Makefile command to create Linux Kernel module.
make all
Install/Load the kernel module into kernel.
insmod cmpe283-1.ko
To verify that the kernel module has been installed run following command.
lsmod
See the output in the system logs:
dmesg
To unload/uninstall the kernel module:
rmmod cmpe283-1

## Making cmpe281-1.diff file: \n
Check and store the initial commit of the official Linux repository.
git status
	Initial commit: 63bdf4284c38a48af21745ceb148a087b190cd21
Commit the changes to git repository.
git add .
git commit -d “CMPE283 Assignment1 FinalCommit JayParekh JainamSheth”
Final Commit: 89803124dfeeca9179ab0bc4398b3ce06875d634
Make the .diff file
git diff 63bdf4284c38a48af21745ceb148a087b190cd21 89803124dfeeca9179ab0bc4398b3ce06875d634 > cmpe283-1.diff

---

## Contents of cmpe281-1.c \n

/*  
 *  cmpe283-1.c - Kernel module for CMPE283 assignment 1
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <asm/msr.h>

#define MAX_MSG 80

/*
 * Model specific registers (MSRs) by the module.
 * See SDM volume 4, section 2.1
 */
#define IA32_VMX_BASIC  0x480
#define IA32_VMX_PINBASED_CTLS	0x481
#define IA32_VMX_PROCBASED_CTLS 0x482
#define IA32_VMX_PROCBASED_CTLS2 0x48B
#define IA32_VMX_EXIT_CTLS 0x483
#define IA32_VMX_ENTRY_CTLS 0x484
#define IA32_VMX_TRUE_PINBASED_CTLS 0x48D
#define IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define IA32_VMX_TRUE_EXIT_CTLS 0x48F
#define IA32_TRUE_ENTRY_CTLS 0x490

/*
 * struct caapability_info
 *
 * Represents a single capability (bit number and description).
 * Used by report_capability to output VMX capabilities.
 */
struct capability_info {
	uint8_t bit;
	const char *name;
};

/*
 * Basic Capabilities
 */
struct capability_info basic[5] =
{
    	{ 55, "True Control Capability" }
};


/*
 * Pinbased Capabilities
 * See SDM volume 3, section 24.6.1
 */
struct capability_info pinbased[5] =
{
	{ 0, "External Interrupt Exiting" },
	{ 3, "NMI Exiting" },
	{ 5, "Virtual NMIs" },
	{ 6, "Activate VMX Preemption Timer" },
	{ 7, "Process Posted Interrupts" }
};

/*
 * Procbased Capabilities 1
 */
struct capability_info procbased[21] =
{
    	{ 2, "Interrupt Window Exiting" },
    	{ 3, "Use TSC Offsetting" },
    	{ 7, "HLT Exiting" },
    	{ 9, "INVLPG Exiting" },
    	{ 10, "MWAIT Exiting" },
    	{ 11, "RDPMC Exiting" },
    	{ 12, "RDTSC Exiting" },
    	{ 15, "CR3 Load Exiting" },
    	{ 16, "CR3 Store Exiting" },
   	{ 19, "CR8 Load Exiting" },
   	{ 20, "CR8 Store Exiting" },
    	{ 21, "Use TPR Shadow" },
    	{ 22, "NMI Window Exiting" },
    	{ 23, "MOV-DR Wxiting" },
    	{ 24, "Unconditional I/O Exiting" },
    	{ 25, "Use I/O Bitmaps" },
    	{ 27, "Monitor Trap Flag" },
    	{ 28, "Use MSR Bitmaps" },
    	{ 29, "MONITOR Exiting" },
    	{ 30, "PAUSE Exiting" },
    	{ 31, "Activate Secondary Controls" }
};

/*
 * Procbased Capabilities 2
 */
struct capability_info procbased2[23] =
{
   	{ 0, "Virtualize APICaccesses" },
    	{ 1, "Enable EPT" },
	{ 2, "Descriptor Table Exiting" },
    	{ 3, "Enable RDTSCP" },
    	{ 4, "Virtualize x2APIC Mode" },
    	{ 5, "Enable VPID" },
    	{ 6, "WBINVD Exiting" },
    	{ 7, "Unrestricted Guest" },
    	{ 8, "APIC Register Virtualization" },
    	{ 9, "Virtual Interrupt Delivery" },
    	{ 10, "PAUSE Loop Exiting" },
    	{ 11, "RDRAND Exiting" },
    	{ 12, "Enable INVPCID" },
   	{ 13, "Enable VM Functions" },
    	{ 14, "VMCS Shadowing" },
    	{ 15, "Enable ENCLS Exiting" },
    	{ 16, "RDSEED Exiting" },
    	{ 17, "Enable PML" },
    	{ 18, "EPT Violation #VE" },
    	{ 19, "Conceal VMX From PT" },
    	{ 20, "Enable XSAVES/XRSTORS" },
    	{ 22, "Mode Based Execute Control" },
    	{ 25, "Use TSC Scaling" }
};

/*
 * Exit Control Capabilities
 */
struct capability_info exitcontrol[11] =
{
    	{ 2, "Save Debug Controls" },
    	{ 9, "Host Addressspace Size" },
    	{ 12, "Load IA32_PERF_GLOB AL_CTRL" },
    	{ 15, "Acknowledge Interrupt on Exit" },
    	{ 18, "Save IA32_PAT" },
    	{ 19, "Load IA32_PAT" },
    	{ 20, "Save IA32_EFER" },
    	{ 21, "Load IA32_EFER" },
    	{ 22, "Save VMXpreemption Timer Value" },
    	{ 23, "Clear IA32_BNDCFGS" },
    	{ 24, "Conceal VMX From PT" }
};

/*
 * Entry Control Capabilities
 */
struct capability_info entrycontrol[9] =
{
    	{ 2, "Load Debug Controls" },
    	{ 9, "IA-32e Mode Guest" },
    	{ 10, "Entry to SMM" },
    	{ 11, "Deactivate Dualmonitor Treatment" },
    	{ 13, "Load IA32_PERF_GLOBA L_CTRL" },
    	{ 14, "Load IA32_PAT" },
    	{ 15, "Load IA32_EFER" },
    	{ 16, "Load IA32_BNDCFGS" },
    	{ 17, "Conceal VMX From PT" }
};

/*
 * True Pinbased Capabilities
 */
struct capability_info truepinbased[5] =
{
    	{ 0, "External Interrupt Exiting" },
    	{ 3, "NMI Exiting" },
    	{ 5, "Virtual NMIs" },
    	{ 6, "Activate VMX Preemption Timer" },
    	{ 7, "Process Posted Interrupts" }
};

/*
 * True Procbased Capabilities
 */
struct capability_info trueprocbased[21] =
{
    	{ 2, "Interrupt Window Exiting" },
    	{ 3, "Use TSC Offsetting" },
    	{ 7, "HLT Exiting" },
    	{ 9, "INVLPG Exiting" },
    	{ 10, "MWAIT Exiting" },
    	{ 11, "RDPMC Exiting" },
    	{ 12, "RDTSC Exiting" },
    	{ 15, "CR3 Load Exiting" },
    	{ 16, "CR3 Store Exiting" },
    	{ 19, "CR8 Load Exiting" },
    	{ 20, "CR8 Store Exiting" },
    	{ 21, "Use TPR Shadow" },
    	{ 22, "NMI Window Exiting" },
    	{ 23, "MOV-DR Exiting" },
    	{ 24, "Unconditional I/O Exiting" },
    	{ 25, "Use I/O Bitmaps" },
    	{ 27, "Monitor Trap Flag" },
    	{ 28, "Use MSR Bitmaps" },
    	{ 29, "MONITOR Exiting" },
    	{ 30, "PAUSE Exiting" },
    	{ 31, "Activate Secondary Controls" }
};

/* 
 * True Exit Control Capabilities
 */
struct capability_info trueexitcontrol[11] =
{
    	{ 2, "Save Debug Controls" },
    	{ 9, "Host Addressspace Size" },
    	{ 12, "Load IA32_PERF_GLOB AL_CTRL" },
    	{ 15, "Acknowledge Interrupt on Exit" },
    	{ 18, "Save IA32_PAT" },
    	{ 19, "Load IA32_PAT" },
    	{ 20, "Save IA32_EFER" },
    	{ 21, "Load IA32_EFER" },
    	{ 22, "Save VMXpreemption Timer Value" },
    	{ 23, "Clear IA32_BNDCFGS" },
    	{ 24, "Conceal VMX From PT" }
};

/*
 * Entry Control Capabilities
 */
struct capability_info trueentrycontrol[9] =
{
    	{ 2, "Load Debug Controls" },
    	{ 9, "IA-32e Mode Guest" },
    	{ 10, "Entry to SMM" },
    	{ 11, "Deactivate Dualmonitor Treatment" },
    	{ 13, "Load IA32_PERF_GLOBA L_CTRL" },
    	{ 14, "Load IA32_PAT" },
    	{ 15, "Load IA32_EFER" },
    	{ 16, "Load IA32_BNDCFGS" },
    	{ 17, "Conceal VMX From PT" }
};

/*
 * report_capability
 *
 * Reports capabilities present in 'cap' using the corresponding MSR values
 * provided in 'lo' and 'hi'.
 *
 * Parameters:
 *  cap: capability_info structure for this feature
 *  len: number of entries in 'cap'
 *  lo: low 32 bits of capability MSR value describing this feature
 *  hi: high 32 bits of capability MSR value describing this feature
 */
void
report_capability(struct capability_info *cap, uint8_t len, uint32_t lo,
    uint32_t hi)
{
	uint8_t i;
	struct capability_info *c;
	char msg[MAX_MSG];

	memset(msg, 0, sizeof(msg));

	for (i = 0; i < len; i++) {
		c = &cap[i];
		snprintf(msg, 79, "  %s: Can set=%s, Can clear=%s\n",
		    c->name,
		    (hi & (1 << c->bit)) ? "Yes" : "No",
		    !(lo & (1 << c->bit)) ? "Yes" : "No");
		printk(msg);
	}
}

/*
 * detect_vmx_features
 *
 * Detects and prints VMX capabilities of this host's CPU.
 */
void
detect_vmx_features(void)
{
	uint32_t lo, hi;

	/* Basic controls */
    	rdmsr(IA32_VMX_BASIC, lo, hi);
   	pr_info("\n Basic MSR: 0x%llx\n\n",
        	(uint64_t)(lo | (uint64_t)hi << 32));
   	report_capability(basic, 1, lo, hi);	

	/* Pinbased controls */
	rdmsr(IA32_VMX_PINBASED_CTLS, lo, hi);
	pr_info("\n Pinbased Controls MSR: 0x%llx\n\n",
		(uint64_t)(lo | (uint64_t)hi << 32));
	report_capability(pinbased, 5, lo, hi);

	/* Procbased controls */
    	rdmsr(IA32_VMX_PROCBASED_CTLS, lo, hi);
    	pr_info("\n Procbased MSR: 0x%llx\n\n",
        	(uint64_t)(lo | (uint64_t)hi << 32));
    	report_capability(procbased, 21, lo, hi);
	
	/* Procbased controls 2 */
    	rdmsr(IA32_VMX_PROCBASED_CTLS2, lo, hi);
    	pr_info("\n Procbased MSR2: 0x%llx\n\n",
        	(uint64_t)(lo | (uint64_t)hi << 32));
    	report_capability(procbased2, 21, lo, hi);

	/* Exit controls */
    	rdmsr(IA32_VMX_EXIT_CTLS, lo, hi);
    	pr_info("\n Exit controls MSR: 0x%llx\n\n",
        	(uint64_t)(lo | (uint64_t)hi << 32));
    	report_capability(exitcontrol, 11, lo, hi);

	/* Entry controls */
    	rdmsr(IA32_VMX_ENTRY_CTLS, lo, hi);
   	pr_info("\n Entry controls MSR: 0x%llx\n\n",
        	(uint64_t)(lo | (uint64_t)hi << 32));
    	report_capability(entrycontrol, 9, lo, hi);

	/* True Pinbased controls */
    	rdmsr(IA32_VMX_TRUE_PINBASED_CTLS, lo, hi);
    	pr_info("\nTrue Pinbased Controls MSR: 0x%llx\n",
        	(uint64_t)(lo | (uint64_t)hi << 32));
    	report_capability(truepinbased, 5, lo, hi);

	/* True Procbased controls */
    	rdmsr(IA32_VMX_TRUE_PROCBASED_CTLS, lo, hi);
    	pr_info("\nTrue Procbased MSR: 0x%llx\n",
        	(uint64_t)(lo | (uint64_t)hi << 32));
    	report_capability(trueprocbased, 21, lo, hi);

	/* True Exit controls */
    	rdmsr(IA32_VMX_TRUE_EXIT_CTLS, lo, hi);
    	pr_info("\nTrue Exit controls MSR: 0x%llx\n",
        	(uint64_t)(lo | (uint64_t)hi << 32));
    	report_capability(trueexitcontrol, 11, lo, hi);

	/* True Entry controls */
    	rdmsr(IA32_TRUE_ENTRY_CTLS, lo, hi);
    	pr_info("\nTrue Entry controls MSR: 0x%llx\n",
        	(uint64_t)(lo | (uint64_t)hi << 32));
    	report_capability(trueentrycontrol, 9, lo, hi);

}

/*
 * init_module
 *
 * Module entry point
 *
 * Return Values:
 *  Always 0
 */
int
init_module(void)
{
	printk(KERN_INFO "\n\n CMPE 283 Assignment 1 Module Start \n\n");

	detect_vmx_features();

	/* 
	 * A non 0 return means init_module failed; module can't be loaded. 
	 */
	return 0;
}

/*
 * cleanup_module
 *
 * Function called on module unload
 */
void
cleanup_module(void)
{
	printk(KERN_INFO "\n\n CMPE 283 Assignment 1 Module Exits \n\n");
	printk(KERN_INFO "\n Submitted by - Jay Parekh, Jainam Sheth \n");
}

---

## Output \n

[ 2536.296519] 
               
                CMPE 283 Assignment 1 Module Start 

[ 2536.296522] 
                Basic MSR: 0xd8100000000001

[ 2536.296523]   True Control Capability: Can set=Yes, Can clear=Yes
[ 2536.296524] 
                Pinbased Controls MSR: 0x3f00000016

[ 2536.296525]   External Interrupt Exiting: Can set=Yes, Can clear=Yes
[ 2536.296526]   NMI Exiting: Can set=Yes, Can clear=Yes
[ 2536.296526]   Virtual NMIs: Can set=Yes, Can clear=Yes
[ 2536.296527]   Activate VMX Preemption Timer: Can set=No, Can clear=Yes
[ 2536.296528]   Process Posted Interrupts: Can set=No, Can clear=Yes
[ 2536.296529] 
                Procbased MSR: 0xfff9fffe0401e172

[ 2536.296529]   Interrupt Window Exiting: Can set=Yes, Can clear=Yes
[ 2536.296530]   Use TSC Offsetting: Can set=Yes, Can clear=Yes
[ 2536.296530]   HLT Exiting: Can set=Yes, Can clear=Yes
[ 2536.296531]   INVLPG Exiting: Can set=Yes, Can clear=Yes
[ 2536.296532]   MWAIT Exiting: Can set=Yes, Can clear=Yes
[ 2536.296532]   RDPMC Exiting: Can set=Yes, Can clear=Yes
[ 2536.296533]   RDTSC Exiting: Can set=Yes, Can clear=Yes
[ 2536.296533]   CR3 Load Exiting: Can set=Yes, Can clear=No
[ 2536.296534]   CR3 Store Exiting: Can set=Yes, Can clear=No
[ 2536.296534]   CR8 Load Exiting: Can set=Yes, Can clear=Yes
[ 2536.296535]   CR8 Store Exiting: Can set=Yes, Can clear=Yes
[ 2536.296536]   Use TPR Shadow: Can set=Yes, Can clear=Yes
[ 2536.296536]   NMI Window Exiting: Can set=Yes, Can clear=Yes
[ 2536.296537]   MOV-DR Wxiting: Can set=Yes, Can clear=Yes
[ 2536.296537]   Unconditional I/O Exiting: Can set=Yes, Can clear=Yes
[ 2536.296538]   Use I/O Bitmaps: Can set=Yes, Can clear=Yes
[ 2536.296538]   Monitor Trap Flag: Can set=Yes, Can clear=Yes
[ 2536.296539]   Use MSR Bitmaps: Can set=Yes, Can clear=Yes
[ 2536.296539]   MONITOR Exiting: Can set=Yes, Can clear=Yes
[ 2536.296540]   PAUSE Exiting: Can set=Yes, Can clear=Yes
[ 2536.296541]   Activate Secondary Controls: Can set=Yes, Can clear=Yes
[ 2536.296542] 
                Procbased MSR2: 0x553cfe00000000

[ 2536.296542]   Virtualize APICaccesses: Can set=No, Can clear=Yes
[ 2536.296543]   Enable EPT: Can set=Yes, Can clear=Yes
[ 2536.296544]   Descriptor Table Exiting: Can set=Yes, Can clear=Yes
[ 2536.296544]   Enable RDTSCP: Can set=Yes, Can clear=Yes
[ 2536.296545]   Virtualize x2APIC Mode: Can set=Yes, Can clear=Yes
[ 2536.296545]   Enable VPID: Can set=Yes, Can clear=Yes
[ 2536.296546]   WBINVD Exiting: Can set=Yes, Can clear=Yes
[ 2536.296546]   Unrestricted Guest: Can set=Yes, Can clear=Yes
[ 2536.296547]   APIC Register Virtualization: Can set=No, Can clear=Yes
[ 2536.296548]   Virtual Interrupt Delivery: Can set=No, Can clear=Yes
[ 2536.296548]   PAUSE Loop Exiting: Can set=Yes, Can clear=Yes
[ 2536.296549]   RDRAND Exiting: Can set=Yes, Can clear=Yes
[ 2536.296549]   Enable INVPCID: Can set=Yes, Can clear=Yes
[ 2536.296550]   Enable VM Functions: Can set=Yes, Can clear=Yes
[ 2536.296550]   VMCS Shadowing: Can set=No, Can clear=Yes
[ 2536.296551]   Enable ENCLS Exiting: Can set=No, Can clear=Yes
[ 2536.296551]   RDSEED Exiting: Can set=Yes, Can clear=Yes
[ 2536.296552]   Enable PML: Can set=No, Can clear=Yes
[ 2536.296553]   EPT Violation #VE: Can set=Yes, Can clear=Yes
[ 2536.296553]   Conceal VMX From PT: Can set=No, Can clear=Yes
[ 2536.296554]   Enable XSAVES/XRSTORS: Can set=Yes, Can clear=Yes
[ 2536.296555] 
                Exit controls MSR: 0xbfffff00036dff

[ 2536.296555]   Save Debug Controls: Can set=Yes, Can clear=No
[ 2536.296556]   Host Addressspace Size: Can set=Yes, Can clear=Yes
[ 2536.296557]   Load IA32_PERF_GLOB AL_CTRL: Can set=Yes, Can clear=Yes
[ 2536.296557]   Acknowledge Interrupt on Exit: Can set=Yes, Can clear=Yes
[ 2536.296558]   Save IA32_PAT: Can set=Yes, Can clear=Yes
[ 2536.296558]   Load IA32_PAT: Can set=Yes, Can clear=Yes
[ 2536.296559]   Save IA32_EFER: Can set=Yes, Can clear=Yes
[ 2536.296559]   Load IA32_EFER: Can set=Yes, Can clear=Yes
[ 2536.296560]   Save VMXpreemption Timer Value: Can set=No, Can clear=Yes
[ 2536.296561]   Clear IA32_BNDCFGS: Can set=Yes, Can clear=Yes
[ 2536.296561]   Conceal VMX From PT: Can set=No, Can clear=Yes
[ 2536.296562] 
                Entry controls MSR: 0x1f3ff000011ff

[ 2536.296563]   Load Debug Controls: Can set=Yes, Can clear=No
[ 2536.296563]   IA-32e Mode Guest: Can set=Yes, Can clear=Yes
[ 2536.296564]   Entry to SMM: Can set=No, Can clear=Yes
[ 2536.296564]   Deactivate Dualmonitor Treatment: Can set=No, Can clear=Yes
[ 2536.296565]   Load IA32_PERF_GLOBA L_CTRL: Can set=Yes, Can clear=Yes
[ 2536.296566]   Load IA32_PAT: Can set=Yes, Can clear=Yes
[ 2536.296566]   Load IA32_EFER: Can set=Yes, Can clear=Yes
[ 2536.296567]   Load IA32_BNDCFGS: Can set=Yes, Can clear=Yes
[ 2536.296567]   Conceal VMX From PT: Can set=No, Can clear=Yes
[ 2536.296568] 
               True Pinbased Controls MSR: 0x3f00000016
[ 2536.296569]   External Interrupt Exiting: Can set=Yes, Can clear=Yes
[ 2536.296570]   NMI Exiting: Can set=Yes, Can clear=Yes
[ 2536.296570]   Virtual NMIs: Can set=Yes, Can clear=Yes
[ 2536.296571]   Activate VMX Preemption Timer: Can set=No, Can clear=Yes
[ 2536.296571]   Process Posted Interrupts: Can set=No, Can clear=Yes
[ 2536.296573] 
               True Procbased MSR: 0xfff9fffe04006172
[ 2536.296573]   Interrupt Window Exiting: Can set=Yes, Can clear=Yes
[ 2536.296574]   Use TSC Offsetting: Can set=Yes, Can clear=Yes
[ 2536.296574]   HLT Exiting: Can set=Yes, Can clear=Yes
[ 2536.296575]   INVLPG Exiting: Can set=Yes, Can clear=Yes
[ 2536.296575]   MWAIT Exiting: Can set=Yes, Can clear=Yes
[ 2536.296576]   RDPMC Exiting: Can set=Yes, Can clear=Yes
[ 2536.296576]   RDTSC Exiting: Can set=Yes, Can clear=Yes
[ 2536.296577]   CR3 Load Exiting: Can set=Yes, Can clear=Yes
[ 2536.296577]   CR3 Store Exiting: Can set=Yes, Can clear=Yes
[ 2536.296578]   CR8 Load Exiting: Can set=Yes, Can clear=Yes
[ 2536.296579]   CR8 Store Exiting: Can set=Yes, Can clear=Yes
[ 2536.296579]   Use TPR Shadow: Can set=Yes, Can clear=Yes
[ 2536.296580]   NMI Window Exiting: Can set=Yes, Can clear=Yes
[ 2536.296580]   MOV-DR Exiting: Can set=Yes, Can clear=Yes
[ 2536.296581]   Unconditional I/O Exiting: Can set=Yes, Can clear=Yes
[ 2536.296581]   Use I/O Bitmaps: Can set=Yes, Can clear=Yes
[ 2536.296582]   Monitor Trap Flag: Can set=Yes, Can clear=Yes
[ 2536.296582]   Use MSR Bitmaps: Can set=Yes, Can clear=Yes
[ 2536.296583]   MONITOR Exiting: Can set=Yes, Can clear=Yes
[ 2536.296583]   PAUSE Exiting: Can set=Yes, Can clear=Yes
[ 2536.296584]   Activate Secondary Controls: Can set=Yes, Can clear=Yes
[ 2536.296585] 
               True Exit controls MSR: 0xbfffff00036dfb
[ 2536.296586]   Save Debug Controls: Can set=Yes, Can clear=Yes
[ 2536.296586]   Host Addressspace Size: Can set=Yes, Can clear=Yes
[ 2536.296587]   Load IA32_PERF_GLOB AL_CTRL: Can set=Yes, Can clear=Yes
[ 2536.296587]   Acknowledge Interrupt on Exit: Can set=Yes, Can clear=Yes
[ 2536.296588]   Save IA32_PAT: Can set=Yes, Can clear=Yes
[ 2536.296589]   Load IA32_PAT: Can set=Yes, Can clear=Yes
[ 2536.296589]   Save IA32_EFER: Can set=Yes, Can clear=Yes
[ 2536.296590]   Load IA32_EFER: Can set=Yes, Can clear=Yes
[ 2536.296590]   Save VMXpreemption Timer Value: Can set=No, Can clear=Yes
[ 2536.296591]   Clear IA32_BNDCFGS: Can set=Yes, Can clear=Yes
[ 2536.296591]   Conceal VMX From PT: Can set=No, Can clear=Yes
[ 2536.296592] 
               True Entry controls MSR: 0x1f3ff000011fb
[ 2536.296593]   Load Debug Controls: Can set=Yes, Can clear=Yes
[ 2536.296594]   IA-32e Mode Guest: Can set=Yes, Can clear=Yes
[ 2536.296594]   Entry to SMM: Can set=No, Can clear=Yes
[ 2536.296595]   Deactivate Dualmonitor Treatment: Can set=No, Can clear=Yes
[ 2536.296595]   Load IA32_PERF_GLOBA L_CTRL: Can set=Yes, Can clear=Yes
[ 2536.296596]   Load IA32_PAT: Can set=Yes, Can clear=Yes
[ 2536.296596]   Load IA32_EFER: Can set=Yes, Can clear=Yes
[ 2536.296597]   Load IA32_BNDCFGS: Can set=Yes, Can clear=Yes
[ 2536.296597]   Conceal VMX From PT: Can set=No, Can clear=Yes
