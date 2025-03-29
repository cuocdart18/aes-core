fun main() {
    //128
    val aes_128 = Aes(Aes.KeyLength.AES_128, "Key-test-cho-aes-128")
    aes_128.encryptFile("src/input.txt", "src/out-enc-128.txt")
    println(aes_128.getError())
    aes_128.decryptFile("src/out-enc-128.txt", "src/out-dec-128.txt")
    println(aes_128.getError())

    //192
    val aes_192 = Aes(Aes.KeyLength.AES_192, "Th-key-rat-nho")
    aes_192.encryptFile("src/input.txt", "src/out-enc-192.txt")
    println(aes_192.getError())
    aes_192.decryptFile("src/out-enc-192.txt", "src/out-dec-192.txt")
    println(aes_192.getError())

    //256
    val aes_256 = Aes(Aes.KeyLength.AES_256, "Th-key-rat-dai-pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp")
    aes_256.encryptFile("src/input.txt", "src/out-enc-256.txt")
    println(aes_256.getError())
    aes_256.decryptFile("src/out-enc-256.txt", "src/out-dec-256.txt")
    println(aes_256.getError())
}