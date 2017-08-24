#include "apple_ave_utils.h"
#include "iokit.h"
#include "log.h"
#include "iosurface_utils.h"



/*
 * Function name: 	apple_ave_utils_get_connection
 * Description:		Establishes a new connection to an AppleAVE2DriverUserClient object.
 * Returns:			kern_return_t and the connection as an output parameter.
 */

kern_return_t apple_ave_utils_get_connection(io_connect_t * conn_out) {
	kern_return_t ret = KERN_SUCCESS;
	io_connect_t connection = 0;
	mach_port_t master_port = 0;
	io_iterator_t itr = 0;
	io_service_t service = 0;
	io_name_t service_name;

	ret = host_get_io_master(mach_host_self(), &master_port);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Failed getting master port");
		goto cleanup;
	}

	ret = IOServiceGetMatchingServices(master_port, IOServiceMatching(IOKIT_ALL_SERVICES), &itr);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("Failed getting matching services");
		goto cleanup;
	}

	while(IOIteratorIsValid(itr) && (service = IOIteratorNext(itr))) {

		ret = IORegistryEntryGetName(service, service_name);
		if (KERN_SUCCESS != ret)
		{
			ERROR_LOG("Error retrieving name");
			continue;
		}

		if (strcmp(service_name, IOKIT_SERVICE_APPLE_AVE_NAME))
		{
			continue;
		}

		ret = IOServiceOpen(service, mach_task_self(), 0, &connection);
		if (KERN_SUCCESS != ret)
		{
			ERROR_LOG("Error opening service %s", service_name);
			continue;
		}

		break;
	}

	if (0 == connection)
	{
		ERROR_LOG("Service %s not found!", IOKIT_SERVICE_APPLE_AVE_NAME);
		ret = KERN_ABORTED;
	}

cleanup:

	if (KERN_SUCCESS == ret)
	{
		*conn_out = connection;
	}

	if (itr)
	{
		itr = 0;
	}

	return ret;

}



/*
 * Function name: 	apple_ave_utils_add_client
 * Description:		Adds a client to something. Needed to crash.
 * Returns:			kern_return_t from the IOKit call.
 */

kern_return_t apple_ave_utils_add_client(io_connect_t conn) {
	kern_return_t ret = KERN_SUCCESS;
	char input_buffer[IOKIT_ADD_CLIENT_INPUT_BUFFER_SIZE] = {0};
	size_t output_buffer_size = IOKIT_ADD_CLIENT_OUTPUT_BUFFER_SIZE;
	char output_buffer[output_buffer_size];

	memset(output_buffer, 0, output_buffer_size);

	ret = IOConnectCallMethod(conn,
		APPLEAVE2_EXTERNAL_METHOD_ADD_CLIENT,
		NULL, 0,
		input_buffer, sizeof(input_buffer),
		NULL, 0,
		output_buffer, &output_buffer_size);

	return ret;
}


/*
 * Function name: 	apple_ave_utils_remove_client
 * Description:		Removes a client... from being added to something.
 * Returns:			kern_return_t from the IOKit call.
 */

kern_return_t apple_ave_utils_remove_client(io_connect_t conn) {
	kern_return_t ret = KERN_SUCCESS;
	char input_buffer[IOKIT_REMOVE_CLIENT_INPUT_BUFFER_SIZE] = {0};
	size_t output_buffer_size = IOKIT_REMOVE_CLIENT_OUTPUT_BUFFER_SIZE;
	char output_buffer[output_buffer_size];

	memset(output_buffer, 0, output_buffer_size);

	ret = IOConnectCallMethod(conn,
		APPLEAVE2_EXTERNAL_METHOD_REMOVE_CLIENT,
		NULL, 0,
		input_buffer, sizeof(input_buffer),
		NULL, 0,
		output_buffer, &output_buffer_size);

	return ret;
}


/*
 * Function name: 	apple_ave_utils_encode_frame
 * Description:		Wrapper for the EncodeFrame external method.
 * Returns:			kern_return_t.
 */

kern_return_t apple_ave_utils_encode_frame(io_connect_t conn, void * input_buffer,
	void * output_buffer) {
	
	kern_return_t ret = KERN_SUCCESS;	
	size_t output_buffer_size = IOKIT_ENCODE_FRAME_OUTPUT_BUFFER_SIZE;

	ret = IOConnectCallMethod(conn,
		APPLEAVE2_EXTERNAL_METHOD_ENCODE_FRAME,
		NULL, 0,
		input_buffer, IOKIT_ENCODE_FRAME_INPUT_BUFFER_SIZE,
		NULL, 0,
		output_buffer, &output_buffer_size);

	return ret;
}




/*
 * Function name: 	apple_ave_utils_prepare_to_encode_frames
 * Description:		Wrapper for the PrepareToEncodeFrames external method.
 * Returns:			kern_return_t and output buffer as an output parameter.
 */

kern_return_t apple_ave_utils_prepare_to_encode_frames(io_connect_t conn, void * input_buffer,
 void * output_buffer) {
	
	kern_return_t ret = KERN_SUCCESS;
	size_t output_buffer_size = ENCODE_FRAME_OUTPUT_BUFFER_SIZE;

	ret = IOConnectCallMethod(conn,
		APPLEAVE2_EXTERNAL_METHOD_PREPARE_TO_ENCODE_FRAMES,
		NULL, 0,
		input_buffer, ENCODE_FRAME_INPUT_BUFFER_SIZE,
		NULL, 0,
		output_buffer, &output_buffer_size);


	return ret;	
}

/*
 * Function name: 	apple_ave_utils_set_session_settings
 * Description:		Sets the session settings for the AVE client.
 * Returns:			kern_return_t.
 */

kern_return_t apple_ave_utils_set_session_settings(io_connect_t conn, void * input_buffer, void * output_buffer) {
	
	kern_return_t ret = KERN_SUCCESS;
	char output_buffer_local[ENCODE_FRAME_OUTPUT_BUFFER_SIZE] = {0};
	size_t output_buffer_size = sizeof(output_buffer_local);


	ret = IOConnectCallMethod(conn,
		APPLEAVE2_EXTERNAL_METHOD_SET_SESSION_SETTINGS,
		NULL, 0,
		input_buffer, ENCODE_FRAME_INPUT_BUFFER_SIZE,
		NULL, 0,
		output_buffer_local, &output_buffer_size);

	if (output_buffer && KERN_SUCCESS == ret)
	{
		memcpy(output_buffer, output_buffer_local, sizeof(output_buffer_local));
	}

	return ret;
}

