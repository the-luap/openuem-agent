# Authenticode verification fixture

`ev-signed-file.exe` is copied unchanged from
`golang.org/x/sys@v0.47.0/windows/testdata/ev-signed-file.exe`.
Its original BSD license is retained in `LICENSE`.

SHA-256: `5d92ebb58e887fe05878ac8805bc125eb47916764678668cd8cbd4c092cd6667`.

The Go project generated this small executable from a program that prints
`Hello Gophers!`, then applied an EV Authenticode signature with a DigiCert
timestamp. The upstream fixture documentation is available at
[Go x/sys testdata](https://github.com/golang/sys/tree/v0.47.0/windows/testdata).

Our tests only copy, inspect and deliberately corrupt its bytes. They never run
the program, import its certificates, change OS trust or disable revocation checks.
The fixture is test data only and must not be included in an agent installer.
