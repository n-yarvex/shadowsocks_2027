package main

import (
    "crypto/ecdh"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "log"
)

func main() {
    privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
    if err != nil {
        log.Fatal(err)
    }
    publicKey := privateKey.PublicKey()

    fmt.Println("Private Key (for server.json):")
    fmt.Println(base64.StdEncoding.EncodeToString(privateKey.Bytes()))
    fmt.Println()
    fmt.Println("Public Key (for client.json):")
    fmt.Println(base64.StdEncoding.EncodeToString(publicKey.Bytes()))
}
