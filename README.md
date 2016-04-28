# Standalone AES-GCM
mbed TLS has an AES-GCM implementation, but it is tied to system libraries and to the rest of the library's code. I've made it standalone so that you can use just aes-gcm (one great use is for embedded systems).

Note the terrible hack in cipher_wrap.c to get rid of calloc:

```c
static mbedtls_gcm_context gcm_ctx;
...
static void *gcm_ctx_alloc( void )
{
    void *ctx = &gcm_ctx;
```

That is, the "alloc" function just returns a pointer to a static variable. The ability to create multiple independent contexts is now broken. That's ok with me!
