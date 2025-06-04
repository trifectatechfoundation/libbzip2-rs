# Fuzz

## Seed corpus

* https://github.com/trifectatechfoundation/compression-corpus
* https://gitlab.com/bzip2/bzip2-testfiles
* See the GitHub workflow definitions for more information on seed corpus usage

## Fuzzer dictionary

* There is an existing bzip2 format dictionary: https://github.com/google/fuzzing/blob/master/dictionaries/bz2.dict
* This could be useful for fuzz tests which consume compressed input and attempt to decompress it
* However, there are only very few common input chunks that bzip2 streams share with each other, so the practical benefits of running the fuzzer with this dictionary is likely limited
* See https://llvm.org/docs/LibFuzzer.html#dictionaries for more background