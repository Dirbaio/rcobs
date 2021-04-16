# rcobs

[![Documentation](https://docs.rs/rcobs/badge.svg)](https://docs.rs/rcobs)

Reverse-COBS encoding (rCOBS) is a variant of [COBS encoding](https://en.wikipedia.org/wiki/Consistent_Overhead_Byte_Stuffing) 
designed to allow encoding with zero lookahead.

COBS and rCOBS are useful for framing a stream of messages for transmission over a pipe of bytes (like UART or TCP).
COBS encoding ensures encoded messages don't contain `0x00` bytes, so the `0x00` byte can then be used as a message separator.

Standard COBS splits the input into zero-byte-separated chunks of up to 254 bytes, and prefixes them with 
a length byte. This requires a lookahead of up to 254 bytes when doing streaming encoding.

rCOBS outputs the length byte at the *end* of the chunk instead of at the start, completely
eliminating the lookahead requirement for encoding. The tradeoff is decoding now has to be done starting
from the *end* of the message backwards, so no lookahead is possible. The message has to be 
read in its entirety before it can be decoded.

This makes rCOBS ideal for situations where data is *encoded* in constrained, embedded systems and *decoded* in 
more capable systems, where the full buffering requirement is not a problem. 

## Examples

Chunks are delimited by double-spaces for your convenience.

```
Message:        11 22 33 44
COBS-encoded:   05 11 22 33 44
rCOBS-encoded:  11 22 33 44 05

Message:        11 22 00  33
COBS-encoded:   03 11 22  02 33
rCOBS-encoded:  11 22 03  33 02

Message:        11 00  00  00  42 42 42
COBS-encoded:   02 11  01  01  04 42 42 42
rCOBS-encoded:  11 02  01  01  42 42 42 04
```

## License

This work is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
