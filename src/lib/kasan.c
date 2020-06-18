/*
 * This file contains shadow memory manipulation code.
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
 *
 * Some code borrowed from https://github.com/xairy/kasan-prototype by
 *        Andrey Konovalov <andreyknvl@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <console/console.h>
#include <assert.h>
#include <kasan.h>
#include <symbols.h>
#include <commonlib/bsd/helpers.h>
#include <lib.h>

static void *kasan_memset(void *addr, int c, size_t len)
{
	check_memory_region((unsigned long)addr, len, true, _RET_IP_);

	return __builtin_memset(addr, c, len);
}

static void *kasan_memcpy(void *dest, const void *src, size_t len)
{
	check_memory_region((unsigned long)src, len, false, _RET_IP_);
	check_memory_region((unsigned long)dest, len, true, _RET_IP_);

	return __builtin_memcpy(dest, src, len);
}

/*
 * Poisons the shadow memory for 'size' bytes starting from 'addr'.
 * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
 */
static void kasan_poison_shadow(const void *address, size_t size, u8 value)
{
	void *shadow_start, *shadow_end;

	shadow_start = kasan_mem_to_shadow(address);
	shadow_end = kasan_mem_to_shadow(address + size);

	kasan_memset(shadow_start, value, shadow_end - shadow_start);
}

void kasan_unpoison_shadow(const void *address, size_t size)
{
	kasan_poison_shadow(address, size, 0);

	if (size & KASAN_SHADOW_MASK) {
		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
		*shadow = size & KASAN_SHADOW_MASK;
	}
}

/*
 * All functions below always inlined so compiler could
 * perform better optimizations in each of __asan_loadX/__assn_storeX
 * depending on memory access size X.
 */
static __always_inline bool memory_is_poisoned_1(unsigned long addr)
{
	s8 shadow_value = *(s8 *)kasan_mem_to_shadow((void *)addr);

	if (unlikely(shadow_value)) {
		s8 last_accessible_byte = addr & KASAN_SHADOW_MASK;
		return unlikely(last_accessible_byte >= shadow_value);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_2_4_8(unsigned long addr,
						unsigned long size)
{
	u8 *shadow_addr = (u8 *)kasan_mem_to_shadow((void *)addr);

	/*
	 * Access crosses 8(shadow size)-byte boundary. Such access maps
	 * into 2 shadow bytes, so we need to check them both.
	 */
	if (unlikely(((addr + size - 1) & KASAN_SHADOW_MASK) < size - 1))
		return *shadow_addr || memory_is_poisoned_1(addr + size - 1);

	return memory_is_poisoned_1(addr + size - 1);
}

static __always_inline bool memory_is_poisoned_16(unsigned long addr)
{
	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);

	/* Unaligned 16-bytes access maps into 3 shadow bytes. */
	if (unlikely(!IS_ALIGNED(addr, KASAN_SHADOW_SCALE_SIZE)))
		return *shadow_addr || memory_is_poisoned_1(addr + 15);

	return *shadow_addr;
}

static __always_inline unsigned long bytes_is_nonzero(const u8 *start,
					size_t size)
{
	while (size) {
		if (unlikely(*start))
			return (unsigned long)start;
		start++;
		size--;
	}

	return 0;
}

static __always_inline unsigned long memory_is_nonzero(const void *start,
						const void *end)
{
	unsigned int words;
	unsigned long ret;
	unsigned int prefix = (unsigned long)start % 8;

	if (end - start <= 16)
		return bytes_is_nonzero(start, end - start);

	if (prefix) {
		prefix = 8 - prefix;
		ret = bytes_is_nonzero(start, prefix);
		if (unlikely(ret))
			return ret;
		start += prefix;
	}

	words = (end - start) / 8;
	while (words) {
		if (unlikely(*(u64 *)start))
			return bytes_is_nonzero(start, 8);
		start += 8;
		words--;
	}

	return bytes_is_nonzero(start, (end - start) % 8);
}

static __always_inline bool memory_is_poisoned_n(unsigned long addr,
						size_t size)
{
	unsigned long ret;

	ret = memory_is_nonzero(kasan_mem_to_shadow((void *)addr),
			kasan_mem_to_shadow((void *)addr + size - 1) + 1);

	if (unlikely(ret)) {
		unsigned long last_byte = addr + size - 1;
		s8 *last_shadow = (s8 *)kasan_mem_to_shadow((void *)last_byte);

		if (unlikely(ret != (unsigned long)last_shadow ||
			((long)(last_byte & KASAN_SHADOW_MASK) >= *last_shadow)))
			return true;
	}
	return false;
}

static __always_inline bool memory_is_poisoned(unsigned long addr, size_t size)
{
	if (__builtin_constant_p(size)) {
		switch (size) {
		case 1:
			return memory_is_poisoned_1(addr);
		case 2:
		case 4:
		case 8:
			return memory_is_poisoned_2_4_8(addr, size);
		case 16:
			return memory_is_poisoned_16(addr);
		default:
			//BUILD_BUG();
			assert(0 && "Not reached");
		}
	}

	return memory_is_poisoned_n(addr, size);
}

static __always_inline void check_memory_region_inline(unsigned long addr,
						size_t size, bool write,
						unsigned long ret_ip)
{
	if (unlikely(size == 0))
		return;

	if (unlikely((void *)addr <
		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
		kasan_report(addr, size, write, ret_ip);
		return;
	}

	if (likely(!memory_is_poisoned(addr, size)))
		return;

	kasan_report(addr, size, write, ret_ip);
}

static void check_memory_region(unsigned long addr, size_t size, bool write,
				unsigned long ret_ip)
{
	check_memory_region_inline(addr, size, write, ret_ip);
}

void kasan_check_read(const volatile void *p, unsigned int size)
{
	check_memory_region((unsigned long)p, size, false, _RET_IP_);
}

void kasan_check_write(const volatile void *p, unsigned int size)
{
	check_memory_region((unsigned long)p, size, true, _RET_IP_);
}

static void register_global(struct kasan_global *global)
{
	size_t aligned_size = ALIGN_UP(global->size, KASAN_SHADOW_SCALE_SIZE);

	kasan_unpoison_shadow(global->beg, global->size);

	kasan_poison_shadow(global->beg + aligned_size,
		global->size_with_redzone - aligned_size,
		KASAN_GLOBAL_REDZONE);
}

void __asan_register_globals(struct kasan_global *globals, size_t size)
{
	int i;

	for (i = 0; i < size; i++)
		register_global(&globals[i]);
}

void __asan_unregister_globals(struct kasan_global *globals, size_t size)
{
}

#define DEFINE_ASAN_LOAD_STORE(size)							\
	void __asan_load##size(unsigned long addr)					\
	{															\
		check_memory_region_inline(addr, size, false, _RET_IP_);\
	}															\
	void __asan_load##size##_noabort(unsigned long addr)		\
	{															\
		check_memory_region_inline(addr, size, false, _RET_IP_);\
	}															\
	void __asan_store##size(unsigned long addr)					\
	{															\
		check_memory_region_inline(addr, size, true, _RET_IP_);	\
	}															\
	void __asan_store##size##_noabort(unsigned long addr)		\
	{															\
		check_memory_region_inline(addr, size, true, _RET_IP_);	\
	}

DEFINE_ASAN_LOAD_STORE(1);
DEFINE_ASAN_LOAD_STORE(2);
DEFINE_ASAN_LOAD_STORE(4);
DEFINE_ASAN_LOAD_STORE(8);
DEFINE_ASAN_LOAD_STORE(16);

void __asan_loadN(unsigned long addr, size_t size)
{
	check_memory_region(addr, size, false, _RET_IP_);
}

void __asan_loadN_noabort(unsigned long addr, size_t size)
{
	check_memory_region(addr, size, false, _RET_IP_);
}

void __asan_storeN(unsigned long addr, size_t size)
{
	check_memory_region(addr, size, true, _RET_IP_);
}

void __asan_storeN_noabort(unsigned long addr, size_t size)
{
	check_memory_region(addr, size, true, _RET_IP_);
}

void __asan_handle_no_return(void)
{
	/* nothing */
}

/* Emitted by compiler to poison large objects when they go out of scope. */
void __asan_poison_stack_memory(const void *addr, size_t size)
{
	/*
	 * Addr is KASAN_SHADOW_SCALE_SIZE-aligned and the object is surrounded
	 * by redzones, so we simply round up size to simplify logic.
	 */
	kasan_poison_shadow(addr, ALIGN_UP(size, KASAN_SHADOW_SCALE_SIZE),
			    KASAN_USE_AFTER_SCOPE);
}

/* Emitted by compiler to unpoison large objects when they go into scope. */
void __asan_unpoison_stack_memory(const void *addr, size_t size)
{
	kasan_unpoison_shadow(addr, size);
}

/* Emitted by compiler to poison alloca()ed objects. */
void __asan_alloca_poison(unsigned long addr, size_t size)
{
	size_t rounded_up_size = ALIGN_UP(size, KASAN_SHADOW_SCALE_SIZE);
	size_t padding_size = ALIGN_UP(size, KASAN_ALLOCA_REDZONE_SIZE) -
			rounded_up_size;
	size_t rounded_down_size = ALIGN_DOWN(size, KASAN_SHADOW_SCALE_SIZE);

	const void *left_redzone = (const void *)(addr -
			KASAN_ALLOCA_REDZONE_SIZE);
	const void *right_redzone = (const void *)(addr + rounded_up_size);

	WARN_ON(!IS_ALIGNED(addr, KASAN_ALLOCA_REDZONE_SIZE));

	kasan_unpoison_shadow((const void *)(addr + rounded_down_size),
			      size - rounded_down_size);
	kasan_poison_shadow(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
			KASAN_ALLOCA_LEFT);
	kasan_poison_shadow(right_redzone,
			padding_size + KASAN_ALLOCA_REDZONE_SIZE,
			KASAN_ALLOCA_RIGHT);
}

/* Emitted by compiler to unpoison alloca()ed areas when the stack unwinds. */
void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
{
	if (unlikely(!stack_top || stack_top > stack_bottom))
		return;

	kasan_unpoison_shadow(stack_top, stack_bottom - stack_top);
}

/* Emitted by the compiler to [un]poison local variables. */
#define DEFINE_ASAN_SET_SHADOW(byte) \
	void __asan_set_shadow_##byte(const void *addr, size_t size)	\
	{								\
		__builtin_memset((void *)addr, 0x##byte, size);			\
	}

DEFINE_ASAN_SET_SHADOW(00);
DEFINE_ASAN_SET_SHADOW(f1);
DEFINE_ASAN_SET_SHADOW(f2);
DEFINE_ASAN_SET_SHADOW(f3);
DEFINE_ASAN_SET_SHADOW(f5);
DEFINE_ASAN_SET_SHADOW(f8);

//******************************************************************

static const void *find_first_bad_addr(const void *addr, size_t size)
{
	u8 shadow_val = *(u8 *)kasan_mem_to_shadow(addr);
	const void *first_bad_addr = addr;

	while (!shadow_val && first_bad_addr < addr + size) {
		first_bad_addr += KASAN_SHADOW_SCALE_SIZE;
		shadow_val = *(u8 *)kasan_mem_to_shadow(first_bad_addr);
	}
	return first_bad_addr;
}

static bool addr_has_shadow(struct kasan_access_info *info)
{
	return (info->access_addr >=
		kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
}

static const char *get_shadow_bug_type(struct kasan_access_info *info)
{
	const char *bug_type = "unknown-crash";
	u8 *shadow_addr;

	info->first_bad_addr = find_first_bad_addr(info->access_addr,
						info->access_size);

	shadow_addr = (u8 *)kasan_mem_to_shadow(info->first_bad_addr);

	/*
	 * If shadow byte value is in [0, KASAN_SHADOW_SCALE_SIZE) we can look
	 * at the next shadow byte to determine the type of the bad access.
	 */
	if (*shadow_addr > 0 && *shadow_addr <= KASAN_SHADOW_SCALE_SIZE - 1)
		shadow_addr++;

	switch (*shadow_addr) {
	case 0 ... KASAN_SHADOW_SCALE_SIZE - 1:
		/*
		 * In theory it's still possible to see these shadow values
		 * due to a data race in the kernel code.
		 */
		bug_type = "out-of-bounds";
		break;
	case KASAN_PAGE_REDZONE:
	case KASAN_KMALLOC_REDZONE:
		bug_type = "slab-out-of-bounds";
		break;
	case KASAN_GLOBAL_REDZONE:
		bug_type = "global-out-of-bounds";
		break;
	case KASAN_STACK_LEFT:
	case KASAN_STACK_MID:
	case KASAN_STACK_RIGHT:
	case KASAN_STACK_PARTIAL:
		bug_type = "stack-out-of-bounds";
		break;
	case KASAN_FREE_PAGE:
	case KASAN_KMALLOC_FREE:
		bug_type = "use-after-free";
		break;
	case KASAN_USE_AFTER_SCOPE:
		bug_type = "use-after-scope";
		break;
	case KASAN_ALLOCA_LEFT:
	case KASAN_ALLOCA_RIGHT:
		bug_type = "alloca-out-of-bounds";
		break;
	}

	return bug_type;
}

static const char *get_wild_bug_type(struct kasan_access_info *info)
{
	const char *bug_type = "unknown-crash";

	/*
	if ((unsigned long)info->access_addr < PAGE_SIZE)
		bug_type = "null-ptr-deref";
	else
	if ((unsigned long)info->access_addr < TASK_SIZE)
		bug_type = "user-memory-access";
	else
		bug_type = "wild-memory-access";
	*/
	return bug_type;
}

static const char *get_bug_type(struct kasan_access_info *info)
{
	if (addr_has_shadow(info))
		return get_shadow_bug_type(info);
	return get_wild_bug_type(info);
}

static void print_error_description(struct kasan_access_info *info)
{
	const char *bug_type = get_bug_type(info);

	printk(BIOS_DEBUG, "BUG: KASAN: %s in %p\n",
		bug_type, (void *)info->ip);
	printk(BIOS_DEBUG, "%s of size %zu at addr %p\n",
		info->is_write ? "Write" : "Read", info->access_size,
		info->access_addr);
}

static void kasan_start_report(unsigned long *flags)
{
	/*
	 * Make sure we don't end up in loop.
	 */
	//kasan_disable_current();
	//spin_lock_irqsave(&report_lock, *flags);
	printk(BIOS_DEBUG, "==================================================================\n");
}

static void kasan_end_report(unsigned long *flags)
{
	printk(BIOS_DEBUG, "==================================================================\n");
	/*
	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
	spin_unlock_irqrestore(&report_lock, *flags);
	if (panic_on_warn)
		panic("panic_on_warn set ...\n");
	kasan_enable_current();*/
}

/*
static struct page *addr_to_page(const void *addr)
{
	if ((addr >= (void *)PAGE_OFFSET) &&
			(addr < high_memory))
		return virt_to_head_page(addr);
	return NULL;
}
*/
static void print_address_description(void *addr)
{
	/*struct page *page = addr_to_page(addr);

	dump_stack();
	pr_err("\n");

	if (page && PageSlab(page)) {
		struct kmem_cache *cache = page->slab_cache;
		void *object = nearest_obj(cache, page,	addr);

		describe_object(cache, object, addr);
	}

	if (kernel_or_module_addr(addr) && !init_task_stack_addr(addr)) {*/
	printk(BIOS_DEBUG, "The buggy address belongs to the variable:\n");
	printk(BIOS_DEBUG, " %p\n", addr);
	/*}

	if (page) {
		pr_err("The buggy address belongs to the page:\n");
		dump_page(page, "kasan: bad access detected");
	}*/
}

static bool row_is_guilty(const void *row, const void *guilty)
{
	return (row <= guilty) && (guilty < row + SHADOW_BYTES_PER_ROW);
}

static int shadow_pointer_offset(const void *row, const void *shadow)
{
	/* The length of ">ff00ff00ff00ff00: " is
	 *    3 + (BITS_PER_LONG/8)*2 chars.
	 */
	return 3 + 2 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
		(shadow - row) / SHADOW_BYTES_PER_BLOCK + 1;
}

static void print_shadow_for_address(const void *addr)
{
	int i;
	const void *shadow = kasan_mem_to_shadow(addr);
	const void *shadow_row;

	shadow_row = (void *)ALIGN_DOWN((unsigned long)shadow,
					SHADOW_BYTES_PER_ROW)
		- SHADOW_ROWS_AROUND_ADDR * SHADOW_BYTES_PER_ROW;

	printk(BIOS_INFO, "Memory state around the buggy address:\n");
	for (i = -SHADOW_ROWS_AROUND_ADDR; i <= SHADOW_ROWS_AROUND_ADDR; i++) {
		const void *kaddr = kasan_shadow_to_mem(shadow_row);
		char buffer[4 + 2 + (BITS_PER_LONG/8)*2];
		char shadow_buf[SHADOW_BYTES_PER_ROW];

		snprintf(buffer, sizeof(buffer),
			(i == 0) ? ">%p: " : " %p: ", kaddr);
		/*
		 * We should not pass a shadow pointer to generic
		 * function, because generic functions may try to
		 * access kasan mapping for the passed address.
		 */
		kasan_memcpy(shadow_buf, shadow_row, SHADOW_BYTES_PER_ROW);

		kasan_hexdump(buffer, shadow_buf, SHADOW_BYTES_PER_ROW);

		if (row_is_guilty(shadow_row, shadow))
			printk(BIOS_INFO, "%*c\n",
				shadow_pointer_offset(shadow_row, shadow), '^');

		shadow_row += SHADOW_BYTES_PER_ROW;
	}
}

static void kasan_report_error(struct kasan_access_info *info)
{
	unsigned long flags;

	kasan_start_report(&flags);

	print_error_description(info);
	printk(BIOS_DEBUG, "\n");

	if (!addr_has_shadow(info)) {
		//dump_stack();
	} else {
		print_address_description((void *)info->access_addr);
		printk(BIOS_DEBUG, "\n");
		print_shadow_for_address(info->first_bad_addr);
	}

	kasan_end_report(&flags);
}

/*
static unsigned long kasan_flags;

#define KASAN_BIT_REPORTED	0
#define KASAN_BIT_MULTI_SHOT	1

static inline bool kasan_report_enabled(void)
{
	if (current->kasan_depth)
		return false;
	if (test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
		return true;
	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
}
*/

void kasan_report(unsigned long addr, size_t size,
		bool is_write, unsigned long ip)
{
	struct kasan_access_info info;

	/*if (likely(!kasan_report_enabled()))
		return;
	*/
	//disable_trace_on_warning();

	info.access_addr = (void *)addr;
	info.first_bad_addr = (void *)addr;
	info.access_size = size;
	info.is_write = is_write;
	info.ip = ip;

	kasan_report_error(&info);
}

void kasan_init(void)
{
	kasan_unpoison_shadow((void *) _data, (size_t) (_eheap - _data));
}
