# Entropy Explained

## What is Shannon entropy?

Shannon entropy measures how unpredictable a block of data is. If you can easily guess the next byte, entropy is low. If every byte looks random, entropy is high.

## Why 0 to 8?

A byte has 8 bits, and entropy is measured in bits per byte:

- **0.0**: every byte is identical. Example: a section filled with zeros.
- **8.0**: all 256 byte values appear equally often, like random data.

Examples:

| Data | Approximate entropy |
| --- | --- |
| `AAAAAAAA...` (one repeated byte) | 0.0 |
| English text | around 4 to 5 |
| Typical compiled code | around 5 to 6.5 |
| Encrypted or well-compressed data | close to 8 |

## Why packed or encrypted data scores high

Packers compress or encrypt a program's code to shrink it or hide it. Compression removes repetition, and encryption makes data look random. Both push byte values toward an even spread, so entropy rises toward 8.

## Why legitimate data can also score high

Many normal files contain compressed data: PNG and JPEG images in `.rsrc`, embedded archives, installers, and some game assets. These can easily exceed 7.0 without any malicious intent.

## High entropy does not prove malware

It only says the bytes are dense and random-looking. Ask what the section is and whether compression or encryption makes sense there. Then look at other evidence such as imports, strings, signatures, and behavior in a safe lab.

## Low entropy does not prove safety

Malware authors can pad sections with repetitive data to dilute the score, or encode payloads in ways that keep entropy moderate. Malicious code can also be plain, unpacked, and low entropy.

## How the 7.0 threshold works in this script

```python
HIGH_ENTROPY_THRESHOLD = 7.0

if entropy >= HIGH_ENTROPY_THRESHOLD:
    status = "INVESTIGATE"
else:
    status = "NORMAL RANGE"
```

- Below 7.0 gives `NORMAL RANGE`.
- Exactly 7.0 gives `INVESTIGATE`.
- Above 7.0 gives `INVESTIGATE`.

The value 7.0 is a common rule of thumb for "worth a closer look". It is not a scientific boundary. `INVESTIGATE` is a prompt for a human analyst, not a verdict.

Back to the [README](../README.md) or the [PE format guide](PE_FILE_FORMAT.md).
