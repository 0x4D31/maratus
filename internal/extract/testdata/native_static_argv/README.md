# Static argument-vector control

Trusted inert source for static analysis. The selected executable differs from
`argv[0]`, and the second argument is an empty C string. Both the vector and
every string must be terminated to recover a complete argument list.

On macOS, compile without running the result:

```sh
clang -arch arm64 -O0 -o /tmp/native-argv-arm64 main.c
clang -arch x86_64 -O0 -o /tmp/native-argv-x86_64 main.c
```

Record the compiler/SDK version, source and binary hashes, and linker settings
alongside comparisons. A successful scan is not proof that the fixture ran.
