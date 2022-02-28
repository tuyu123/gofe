module github.com/fentec-project/gofe

go 1.17

require (
	github.com/fentec-project/bn256 v0.0.0-20190726093940-0d0fc8bfeed0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20211115234514-b4de73f9ece8
)

replace github.com/fentec-project/bn256 v0.0.0-20190726093940-0d0fc8bfeed0 => github.com/tuyu123/bn256 v0.0.0-20220228100430-60bc0213f21b
