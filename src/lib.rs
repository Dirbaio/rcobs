#![cfg_attr(not(feature = "std"), no_std)]

/// Write trait to use with Encoder
pub trait Write {
    type Error;

    /// Write a single byte.
    fn write(&mut self, byte: u8) -> Result<(), Self::Error>;
}

/// Streaming encoder
///
/// Allows encoding of reverse-COBS messages in a streaming fashion, with almost
/// no memory usage (internal state is just one single byte!).
///
/// To encode a message, call [write](Self::write) for each byte in the message, then call [end](Self::end).
/// 
/// You may use the same Encoder instance to encode multiple messages. In this case, you
/// will probably want to separate messages with a `0x00`, which you have to write manually
/// after calling [end](Self::end), for example with `encoder.writer().write(0)`.
pub struct Encoder<W: Write> {
    w: W,
    run: u8,
}

impl<W: Write> Encoder<W> {
    /// Create a new encoder with the given writer.
    pub fn new(w: W) -> Self {
        Self { w, run: 0 }
    }

    /// Mutably borrow the inner writer.
    pub fn writer(&mut self) -> &mut W {
        &mut self.w
    }

    /// Write a message byte.
    pub fn write(&mut self, byte: u8) -> Result<(), W::Error> {
        self.run += 1;
        if byte == 0 {
            self.w.write(self.run)?;
            self.run = 0;
        } else {
            self.w.write(byte)?;
            if self.run == 254 {
                self.w.write(0xFF)?;
                self.run = 0;
            }
        }
        Ok(())
    }

    /// Finish encoding a message.
    ///
    /// This does NOT write a `0x00` separator byte, you must write it yourself
    /// if you so desire.
    pub fn end(&mut self) -> Result<(), W::Error> {
        self.write(0)?;
        Ok(())
    }
}

/// Encode a full message.
///
/// Encodes a single message and returns it as a `Vec`. The returned data does
/// not include any `0x00` separator byte, you have to add it yourself.
///
/// This is a convenience function using [Encoder] internally. For streaming encoding, use [Encoder].
#[cfg(feature = "std")]
pub fn encode(data: &[u8]) -> Vec<u8> {
    struct VecWriter<'a>(&'a mut Vec<u8>);

    impl<'a> Write for VecWriter<'a> {
        type Error = std::convert::Infallible;
        fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
            self.0.push(byte);
            Ok(())
        }
    }

    let mut res = Vec::new();
    let mut enc = Encoder::new(VecWriter(&mut res));
    for &b in data {
        enc.write(b).unwrap();
    }
    enc.end().unwrap();
    res
}

/// Error indicating the decoded data was malformed reverse-COBS.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedError;

/// Decode a full message.
///
/// `data` must be a full reverse-COBS encoded message. Decoding partial
/// messages is not possible. `data` must NOT include any `0x00` separator byte.
#[cfg(feature = "std")]
pub fn decode(data: &[u8]) -> Result<Vec<u8>, MalformedError> {
    let mut res = vec![0; data.len()];
    let mut dp = res.len();
    let mut rp = res.len();

    while dp != 0 {
        let n = data[dp - 1] as usize;
        if n == 0 {
            return Err(MalformedError);
        }

        if n != 255 {
            // push a 0
            rp -= 1;
        }

        if dp < n {
            return Err(MalformedError);
        }
        res[rp + 1 - n..rp].copy_from_slice(&data[dp - n..dp - 1]);
        rp -= n - 1;
        dp -= n;
    }

    // Remove extra zero
    res.pop();

    // Remove unused space at the beginning
    res.drain(0..rp);

    Ok(res)
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn it_works() {
        let tests: &[(&[u8], &[u8])] = &[
            (
                &hex!(""),
                &hex!("01"),
            ), (
                &hex!("00"),
                &hex!("0101"),
            ), (
                &hex!("0000"),
                &hex!("010101"),
            ), (
                &hex!("11220033"),
                &hex!("1122033302"),
            ), (
                &hex!("11000000"),
                &hex!("1102010101"),
            ), (
                &hex!("11223344"),
                &hex!("1122334405"),
            ), (
                &hex!("0011001100110011"),
                &hex!("011102110211021102"),
            ), (
                &hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe"),
                &hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff01"),
            ), (
                &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe"),
                &hex!("010102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff01"),
            ), (
                &hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                &hex!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeffff02"),
            ), (
                &hex!("02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00"),
                &hex!("02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeffff0101"),
            ), (
                &hex!("030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0001"),
                &hex!("030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfefffe0102"),
            ),
        ];

        for (dec, enc) in tests {
            assert_eq!(&encode(dec), enc);
            assert_eq!(&decode(enc).unwrap(), dec);
        }
    }
}
