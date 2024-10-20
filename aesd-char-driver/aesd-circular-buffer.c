/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"
#include <stdio.h>

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    /**
    * TODO: implement per description
    */

    size_t l_char_offset = char_offset;
    size_t acc = 0;
    uint8_t i = buffer->out_offs;
    uint8_t max = 0;

    while(l_char_offset >= acc)
    {
        // printf("acc:%ld char_offset:%ld i:%d\n", acc, l_char_offset, i);
        if(max >= (AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED))
        {
            // there is no data in this position of the buffer, return NULL
            // printf("Index out of bounds!\n");
            return NULL;
        }
        if(i >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
        {
            i = 0;
        }
        acc += buffer->entry[i].size;
        i++;
        max++;
    }
    // when acc > l_char_offset, we have gone past the specified offset, we need to roll back an iteration
    i--;
    acc -= buffer->entry[i].size;
    // printf("data:%s", buffer->entry[i].buffptr);
    *entry_offset_byte_rtn = l_char_offset - acc;
    return &buffer->entry[i];
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description
    */

    // add the entry to the buffer
    buffer->entry[buffer->in_offs] = *add_entry;
    // printf("Added entry to circular buffer. in_offs:%d data:%s, size:%ld\n", buffer->in_offs, buffer->entry[buffer->in_offs].buffptr, buffer->entry[buffer->in_offs].size);

    // increase the in offset, perform overflow check
    buffer->in_offs++;
    if(buffer->in_offs >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
    {
        // in offset has reached the end of the circular buffer, roll back to the first position
        buffer->in_offs = 0;
    }

    // check if the buffer is full
    if (buffer->full == true)
    {
        // Buffer was full, increase out offset with overflow check, in offset was already increased
        buffer->out_offs++;
        if(buffer->out_offs >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
        {
            // out offset has reached the end of the circular buffer, roll back to the first position
            buffer->out_offs = 0;
        }
        // printf("Buffer full -> in_offs:%d out_offs:%d\n", buffer->in_offs, buffer->out_offs);
    }
    else
    {
        // buffer was not full, check if buffer is now full
        if(buffer->in_offs == buffer->out_offs)
        {
            // buffer is full, set full flag
            buffer->full = true;
            // printf("Buffer is now full!\n");
        }
    }
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
