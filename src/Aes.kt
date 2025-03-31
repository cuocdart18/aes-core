import java.io.*
import java.util.*
import kotlin.experimental.xor

enum class KeyLength(private val bitLength: Int, val byteLength: Int = bitLength / 8) {
    AES_128(128),
    AES_192(192),
    AES_256(256)
}

class Aes(private val keyLength: KeyLength, keyString: String) {

    private val key: ByteArray = formatKey(keyString.trim().toByteArray(), keyLength.byteLength)
    private val keyExpanded: ByteArray = when (keyLength) {
        KeyLength.AES_128 -> ByteArray(176)
        KeyLength.AES_192 -> ByteArray(208)
        KeyLength.AES_256 -> ByteArray(240)
    }

    private var initializationVector: ByteArray = byteArrayOf()

    init {
        keyExpansion()
    }

    private fun formatKey(key: ByteArray, targetLen: Int): ByteArray {
        return when {
            key.size > targetLen -> key.copyOf(targetLen)
            key.size < targetLen -> key.copyOf(targetLen).apply {
                fill(0, key.size, targetLen)
            }

            else -> key
        }
    }

    private fun keyExpansion() {
        val nk = keyLength.byteLength / 4
        val nb = 4
        val nr = nk + 6

        var i = 0
        val temp = ByteArray(4)
        var rcon = byteArrayOf(0x01.toByte(), 0x00.toByte(), 0x00.toByte(), 0x08.toByte())

        while (i < nk) {
            for (j in 0..<4) {
                keyExpanded[i * 4 + j] = key[i * 4 + j]
            }
            i++
        }

        while (i < nb * (nr + 1)) {
            for (j in 0..<4) {
                temp[j] = keyExpanded[(i - 1) * 4 + j]
            }
            if (i % nk == 0) {
                rotWord(temp)
                // Substitute bytes in temp with Substitution box
                temp[0] = Sbox[temp[0].toInt() and 0xFF]
                temp[1] = Sbox[temp[1].toInt() and 0xFF]
                temp[2] = Sbox[temp[2].toInt() and 0xFF]
                temp[3] = Sbox[temp[3].toInt() and 0xFF]
                // XOR temp with rcon
                temp[0] = temp[0] xor rcon[0]
                // update rcon
                rcon = rcon.copyOf(4)
                rcon[0] = rcon[0] gmul 0x02
            } else if (nk > 6 && i % nk == 4) {
                temp[0] = Sbox[temp[0].toInt() and 0xFF]
                temp[1] = Sbox[temp[1].toInt() and 0xFF]
                temp[2] = Sbox[temp[2].toInt() and 0xFF]
                temp[3] = Sbox[temp[3].toInt() and 0xFF]
            }

            for (j in 0..<4) {
                keyExpanded[i * 4 + j] = keyExpanded[(i - nk) * 4 + j] xor temp[j]
            }
            i++
        }
    }

    private fun rotWord(word: ByteArray) {
        val tmp = word.copyOf()
        word[0] = tmp[1]
        word[1] = tmp[2]
        word[2] = tmp[3]
        word[3] = tmp[0]
    }

    private fun subBytes(state: ByteArray) {
        for (i in state.indices) {
            state[i] = Sbox[state[i].toInt() and 0xFF]
        }
    }

    private fun shiftRows(state: ByteArray): ByteArray {
        val tmp = state.copyOf()

        state[0] = tmp[0]
        state[1] = tmp[5]
        state[2] = tmp[10]
        state[3] = tmp[15]

        state[4] = tmp[4]
        state[5] = tmp[9]
        state[6] = tmp[14]
        state[7] = tmp[3]

        state[8] = tmp[8]
        state[9] = tmp[13]
        state[10] = tmp[2]
        state[11] = tmp[7]

        state[12] = tmp[12]
        state[13] = tmp[1]
        state[14] = tmp[6]
        state[15] = tmp[11]

        return state
    }

    private fun mixColumns(state: ByteArray) {
        for (i in 0..<4) {
            val col = ByteArray(4)
            for (j in 0..<4) {
                col[j] = state[i + j * 4]
            }
            state[i] = (col[0] gmul 0x02) xor (col[1] gmul 0x03) xor col[2] xor col[3]
            state[i + 4] = (col[1] gmul 0x02) xor (col[2] gmul 0x03) xor col[3] xor col[0]
            state[i + 8] = (col[2] gmul 0x02) xor (col[3] gmul 0x03) xor col[0] xor col[1]
            state[i + 12] = (col[3] gmul 0x02) xor (col[0] gmul 0x03) xor col[1] xor col[2]
        }
    }

    private fun addRoundKey(state: ByteArray, roundKey: ByteArray) {
        for (i in 0..<16) {
            state[i] = state[i] xor roundKey[i]
        }
    }

    private fun invSubBytes(state: ByteArray) {
        for (i in state.indices) {
            state[i] = invSbox[state[i].toInt() and 0xFF]
        }
    }

    private fun invShiftRows(state: ByteArray) {
        val tmp = state.copyOf()

        state[0] = tmp[0]
        state[1] = tmp[13]
        state[2] = tmp[10]
        state[3] = tmp[7]

        state[4] = tmp[4]
        state[5] = tmp[1]
        state[6] = tmp[14]
        state[7] = tmp[11]

        state[8] = tmp[8]
        state[9] = tmp[5]
        state[10] = tmp[2]
        state[11] = tmp[15]

        state[12] = tmp[12]
        state[13] = tmp[9]
        state[14] = tmp[6]
        state[15] = tmp[3]
    }

    private fun invMixColumns(state: ByteArray) {
        for (i in 0..<4) {
            val col = ByteArray(4)
            for (j in 0..<4) {
                col[j] = state[i + j * 4]
            }
            state[i] = (col[0] gmul 0x0E) xor (col[1] gmul 0x0B) xor (col[2] gmul 0x0D) xor (col[3] gmul 0x09)
            state[i + 4] = (col[0] gmul 0x09) xor (col[1] gmul 0x0E) xor (col[2] gmul 0x0B) xor (col[3] gmul 0x0D)
            state[i + 8] = (col[0] gmul 0x0D) xor (col[1] gmul 0x09) xor (col[2] gmul 0x0E) xor (col[3] gmul 0x0B)
            state[i + 12] = (col[0] gmul 0x0B) xor (col[1] gmul 0x0D) xor (col[2] gmul 0x09) xor (col[3] gmul 0x0E)
        }
    }

    private fun encryptBlock(block: ByteArray) {
        val nk = keyLength.byteLength / 4
        val nr = nk + 6
        val nb = 4
        val blockSize = nb * 4

        addRoundKey(block, keyExpanded.copyOfRange(0, blockSize))

        for (round in 1..<nr) {
            subBytes(block)
            shiftRows(block)
            mixColumns(block)
            addRoundKey(block, keyExpanded.copyOfRange(round * nb, (round + 1) * blockSize))
        }

        subBytes(block)
        shiftRows(block)
        addRoundKey(block, keyExpanded.copyOfRange(nr * nb, (nr + 1) * blockSize))
    }

    fun encryptByte(input: ByteArray): ByteArray {
        var result = byteArrayOf()
        try {
            val inputStream = ByteArrayInputStream(input)
            val outputStream = ByteArrayOutputStream()

            var iv = ByteArray(16)
            for (i in iv.indices) {
                iv[i] = (Math.random() * 256).toInt().toByte()
            }
            initializationVector = iv.copyOf()

            val buffer = ByteArray(16)
            var bytesRead: Int
            var addPadding = false

            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                if (bytesRead < 16) {
                    // Padding
                    for (i in bytesRead..<16) {
                        buffer[i] = 0x00.toByte()
                    }
                } else {
                    addPadding = true
                }
                for (i in 0..<16) {
                    buffer[i] = buffer[i] xor iv[i]
                }
                encryptBlock(buffer)
                outputStream.write(buffer)
                iv = buffer.copyOf()
            }

            if (addPadding) {
                for (i in 0..<16) {
                    buffer[i] = 0x00.toByte()
                }
                for (i in 0..<16) {
                    buffer[i] = buffer[i] xor iv[i]
                }
                encryptBlock(buffer)
                outputStream.write(buffer)
            }
            result = outputStream.toByteArray()
            inputStream.close()
            outputStream.flush()
            outputStream.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return result
    }

    private fun decryptBlock(block: ByteArray) {
        val nk = keyLength.byteLength / 4
        val nr = nk + 6
        val nb = 4
        val blockSize = nb * 4

        addRoundKey(block, keyExpanded.copyOfRange(nr * nb, (nr + 1) * blockSize))

        for (round in nr - 1 downTo 1) {
            invShiftRows(block)
            invSubBytes(block)
            addRoundKey(block, keyExpanded.copyOfRange(round * nb, (round + 1) * blockSize))
            invMixColumns(block)
        }

        invShiftRows(block)
        invSubBytes(block)
        addRoundKey(block, keyExpanded.copyOfRange(0, blockSize))
    }

    fun decryptByte(input: ByteArray): ByteArray {
        var result = byteArrayOf()
        try {
            val inputStream = ByteArrayInputStream(input)
            val tempStream = ByteArrayOutputStream() // Temporary stream to store decrypted data

            var iv = initializationVector.copyOf()

            val buffer = ByteArray(16)
            var bytesRead: Int

            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                val tmp = buffer.copyOf()
                decryptBlock(buffer)
                for (i in 0..<16) {
                    buffer[i] = buffer[i] xor iv[i]
                }
                tempStream.write(buffer, 0, bytesRead)
                iv = tmp.copyOf()
            }

            val decryptedData = tempStream.toByteArray()
            var lastIndex = decryptedData.size - 1

            while (lastIndex >= 0 && decryptedData[lastIndex] == 0x00.toByte()) {
                lastIndex--
            }

            result = tempStream.toByteArray().copyOf(lastIndex + 1)
            tempStream.close()
            inputStream.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return result
    }
}