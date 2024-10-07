#ifndef _OHY_MEMORY_H
#define _OHY_MEMORY_H

#include "linux/kernel.h"
#include "linux/slab.h"

__attribute__((unused))
static void* ohy_kmalloc(size_t mem_size, void* type, gfp_t flags)
{
    if (mem_size == 0)
        return NULL;

    void* alloc_buffer = kmalloc(mem_size * sizeof(type), flags);
    
    if (alloc_buffer)
        return alloc_buffer;

    return NULL;
}

__attribute__((unused))
static void* ohy_kcalloc(size_t mem_size, void* type, gfp_t flags)
{
    if (mem_size == 0)
            return NULL;

    void* alloc_buffer = kcalloc(mem_size * sizeof(type), flags);

    if (alloc_buffer)
        return alloc_buffer;

    return NULL;
}

__attribute__((unused))
static void* ohy_kzalloc(size_t mem_size, gfp_t flags)
{
    if (mem_size == 0)
            return NULL;

    void* alloc_buffer = kcalloc(mem_size, flags);

    if (alloc_buffer)
        return alloc_buffer;

    return NULL;
}

__attribute__((unused))
static void* ohy_alloc_array_zero_memory(size_t mem_size, void* type, gfp_t flags)
{
    if (mem_size == 0)
        return NULL;

    void* alloc_buffer = kmalloc_array(mem_size * sizeof(type), flags);

    if (alloc_buffer)
        return alloc_buffer;

    return NULL;
}

__attribute__((unused))
static size_t ohy_getsize(void* buffer)
{
    return ksize(buffer);
}

__attribute__((unused))
static void ohy_freemem(const void* buffer)
{
    kfree(buffer);
}

#endif