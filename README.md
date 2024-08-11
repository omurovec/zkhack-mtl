# zkVerify proof submission

1. build r0 project

```sh
cd r0 && cargo build --release
```

2. copy `r0` to `zkVerify/src/risc0`

```sh
cp -r r0 zkVerify/src/risc0
```

3. generate proof and submit to zkVerify

```sh
cd zkVerify && npm i && npm run generate:single:proof -- risc0
```

### Example proof leaf: `0x0d6ca1d459bfe1cbcff3d15697bca235aefd4fec774fd5ca6a46da22c5614d22`
