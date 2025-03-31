fun main() {
    val data = "Nhung that cay dang khi biet la"
    val byteData = data.toByteArray()
    println("rawData = $data")
    print("byteArrayData = ")
    byteData.printData()

    val aes128 = Aes(KeyLength.AES_128, "mot-cai-key-nao-do")
    var encryptedData = byteArrayOf()
    val encryptedTime = measureTime {
        encryptedData = aes128.encryptByte(byteData)
    }
    print("encryptedData = ")
    encryptedData.printData()

    var decryptedData = byteArrayOf()
    val decryptedTime = measureTime {
        decryptedData = aes128.decryptByte(encryptedData)
    }
    print("decryptedData = ")
    decryptedData.printData()

    println("rawData = ${decryptedData.toString(Charsets.UTF_8)}")

    println("encryptedTime = $encryptedTime us")
    println("decryptedTime = $decryptedTime us")
}