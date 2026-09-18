# xmip-core-identify-jwt

Identify by jwt: reads a bearer token's subject, unverified, from the connection or from the content, with the token riding as proof for the second gate. A technology of [xmip-core-identify](https://github.com/IlleNilsson/xmip-core-identify).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
