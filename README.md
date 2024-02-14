# Implementing MD5 in C

This is my implementation of the [MD5 Message-Digest Algorithm](https://datatracker.ietf.org/doc/html/rfc1321). I did it to learn a little bit about how cryptographic hash functions work. Doing such project can teach you:

- Low-level operations, such as bit-shifts and XORs (I would never dream of dealing with these in my day-to-day, web-development-related job)
- To work with blocks and buffers, and perform paddings when needed

However, it will not necessarily help you understanding **why** the algorithm works. For this one should explore books such as [The Joy of Cryptography](https://joyofcryptography.com/).

> Of course, this is by no means meant to be used in production. You probably shouldn't be using MD5 anyway.

Apart from the original RFC, the main resource that I used to complete this project was [Zunawe's implementation](https://github.com/Zunawe/md5-c). I took some time to understand some of his decisions but found them to be ingenious in the end. Thanks, @Zunaewe! I ended up following a different path, however.

## Compiling and running

Compiling and running should be easy:

```
make
./md5
```

The `main` function will output some messages and their digests:

```
message =Hello, World!
expected=65a8e27d8879283831b664bd8b7f0ad4
result  =65a8e27d8879283831b664bd8b7f0ad4
```

## The implementation

The MD5 algorithm consists of 4 main steps:

1. Append Padding Bits
2. Append Length
3. Initialize MD Buffer
4. Process Message in 16-word Blocks

However, it is easier to think about the input as a stream of bytes, and to begin with steps 3 and 4, leaving 1 and 2 to the end.

With this in mind, check [md5.c](./md5.c) for the actual implementation.
