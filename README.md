# PyRust-TOTP

A Python wrapper around `totp-rs` made for fast and secure 2fa.

## Installation
```
pip install rust-totp
```


## Why Have a Rust Backend?
- I've hunted for many C Implementations that I liked including
    using HACL-HMAC but it didn't really make much sense to try and code
    yet another cython library or C Backend and have to cherry pick the code out and everything and the possibility
    for vulnerabilites to leak through was not something I wanted to have happen to me or others.

- It's more secure this way and less vulnerable to attacks.

- The Library we use has qr code generation support built-in to the project so no need to have to take care of writing your own implementation for it. Not many libraries offer this capability from what I understand.

- More implementations can be added in in the future besides just 
  sha1, sha256 or sha512 in the future if they can be added to the backend.

- It's memory safe and not costly to load and use making it perfect for servers such as fast-api, litestar, aiohttp or flask and many others.



