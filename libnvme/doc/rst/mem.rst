.. c:function:: void * libnvme_alloc (size_t len)

   Allocate zero-initialized memory

**Parameters**

``size_t len``
  Number of bytes to allocate

**Description**

Allocates **len** bytes of zero-initialized memory suitable for use by
libnvme APIs.

**Return**

Pointer to the allocated memory on success, or ``NULL`` on failure.


.. c:function:: void * libnvme_realloc (void *p, size_t len)

   Resize an allocated memory buffer

**Parameters**

``void *p``
  Existing memory buffer to resize

``size_t len``
  New size in bytes

**Description**

Resizes the memory buffer referenced by **p** to **len** bytes. The returned
buffer may be relocated. On successful expansion, any newly allocated
portion of the buffer is zero-initialized.

If **p** is ``NULL``, this function behaves like libnvme_alloc().

**Return**

Pointer to the resized memory buffer on success, or ``NULL`` on failure.
On failure, the original buffer referenced by **p** remains valid and
unchanged.


.. c:function:: void libnvme_free (void *p)

   Free allocated memory

**Parameters**

``void *p``
  Memory buffer to free

**Description**

Releases memory previously allocated by libnvme_alloc(),
libnvme_realloc(), or related libnvme allocation helpers.




.. c:struct:: libnvme_mem_huge

   Huge page memory allocation descriptor

**Definition**

::

  struct libnvme_mem_huge {
    size_t len;
    bool libnvme_alloc;
    void *p;
  };

**Members**

``len``
  Size of the allocated buffer in bytes

``libnvme_alloc``
  Indicates that **p** was allocated using libnvme_alloc()

``p``
  Pointer to the allocated memory buffer


**Description**

Describes a memory buffer allocated by libnvme_alloc_huge(). The structure
stores allocation metadata required for proper cleanup by
libnvme_free_huge().


.. c:function:: void * libnvme_alloc_huge (size_t len, struct libnvme_mem_huge *mh)

   Allocate a huge page-backed memory buffer

**Parameters**

``size_t len``
  Size of the memory buffer in bytes

``struct libnvme_mem_huge *mh``
  Huge memory allocation descriptor

**Description**

Attempts to allocate a memory buffer backed by huge pages. Allocation
details are stored in **mh** and must later be released using
libnvme_free_huge().

**Return**

pointer to the allocated memory buffer on success, or ``NULL`` on
failure.


.. c:function:: void libnvme_free_huge (struct libnvme_mem_huge *mh)

   Free a huge page-backed memory buffer

**Parameters**

``struct libnvme_mem_huge *mh``
  Huge memory allocation descriptor

**Description**

Releases resources associated with a buffer allocated by
libnvme_alloc_huge(). The descriptor contents are no longer valid after
this call.


