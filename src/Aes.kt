import java.io.*
import kotlin.experimental.xor


class Aes(private val keyLength: KeyLength, keyString: String ) {
    // Normalized key
    private val key: ByteArray = normalizeKey(keyString.trim().toByteArray(), keyLength.byteLength)
    private val keyExpanded: ByteArray = when (keyLength) {
        KeyLength.AES_128 -> ByteArray(176)
        KeyLength.AES_192 -> ByteArray(208)
        KeyLength.AES_256 -> ByteArray(240)
    }
    private var error = false
    private var errorMessage = ""


    init {
        keyExpansion()
    }

    /**
     * AES key length
     */
    enum class KeyLength(private val bitLength: Int, val byteLength: Int = bitLength / 8) {
        AES_128(128),
        AES_192(192),
        AES_256(256)
    }

    /**
     * Normalize key to target length
     * @param key: ByteArray
     * @param targetLen: Int (KeyLength.byteLength)
     * @return normalized key: ByteArray
     */
    private fun normalizeKey(key: ByteArray, targetLen: Int): ByteArray {
        return when {
            key.size > targetLen -> key.copyOf(targetLen) // Cắt bớt nếu dài hơn
            key.size < targetLen -> key.copyOf(targetLen).apply { fill(0, key.size, targetLen) } // Padding nếu ngắn hơn
            else -> key
        }
    }

    /**
     * Substitute bytes in state with Substitution box
     * @param state: ByteArray
     */
    private fun subBytes(state: ByteArray) {
        for (i in state.indices) {
            state[i] = Sbox[state[i].toInt() and 0xFF]
        }
    }

    /**
     * Substitute bytes in state with Inv Substitution box
     * @param state: ByteArray
     */
    private fun invSubBytes(state: ByteArray) {
        for (i in state.indices) {
            state[i] = InvSbox[state[i].toInt() and 0xFF]
        }
    }


    /**
     * Shift rows in state
     * @param state: ByteArray
     * @return shifted state: ByteArray
     */
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

    /**
     * Shift rows in state
     * @param state: ByteArray
     * @return shifted state: ByteArray
     */
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

    /**
     * Multiply two numbers in the Galois Field using the "Russian Peasant Multiplication" algorithm
     * @param a The first number
     * @param b The second number
     * @return The product of a and b in the Galois Field
     */
    private fun gmul(a: Byte, b: Byte): Byte {
        var p = 0
        var aa = a.toInt() and 0xFF // convert to unsigned int
        var bb = b.toInt() and 0xFF

        for (i in 0 .. 8) {
            if ((bb and 1) != 0) {
                p = p xor aa
            }
            val hiBitSet = aa and 0x80
            aa = (aa shl 1) and 0xFF
            if (hiBitSet != 0) {
                aa = aa xor 0x1B // XOR với đa thức sinh của AES
            }
            bb = bb shr 1
        }
        return (p and 0xFF).toByte()
    }

    /**
     * Mix columns in state
     * @param state: ByteArray
     */
    private fun mixColumns(state: ByteArray) {
        for (i in 0..<4) {
            val col = ByteArray(4)
            for (j in 0..<4) {
                col[j] = state[i + j * 4]
            }
            state[i] = gmul(0x02, col[0]) xor gmul(0x03, col[1]) xor col[2] xor col[3]
            state[i + 4] = gmul(0x02, col[1]) xor gmul(0x03, col[2]) xor col[3] xor col[0]
            state[i + 8] = gmul(0x02, col[2]) xor gmul(0x03, col[3]) xor col[0] xor col[1]
            state[i + 12] = gmul(0x02, col[3]) xor gmul(0x03, col[0]) xor col[1] xor col[2]
        }
    }

    /**
     * Mix columns in state
     * @param state: ByteArray
     */
    private fun invMixColumns(state: ByteArray) {
        for (i in 0..<4) {
            val col = ByteArray(4)
            for (j in 0..<4) {
                col[j] = state[i + j * 4]
            }
            state[i] = gmul(0x0E, col[0]) xor gmul(0x0B, col[1]) xor gmul(0x0D, col[2]) xor gmul(0x09, col[3])
            state[i + 4] = gmul(0x09, col[0]) xor gmul(0x0E, col[1]) xor gmul(0x0B, col[2]) xor gmul(0x0D, col[3])
            state[i + 8] = gmul(0x0D, col[0]) xor gmul(0x09, col[1]) xor gmul(0x0E, col[2]) xor gmul(0x0B, col[3])
            state[i + 12] = gmul(0x0B, col[0]) xor gmul(0x0D, col[1]) xor gmul(0x09, col[2]) xor gmul(0x0E, col[3])
        }
    }

    /**
     * Add round key to state
     * @param state: ByteArray
     * @param roundKey: ByteArray
     */
    private fun addRoundKey(state: ByteArray, roundKey: ByteArray) {
        for (i in 0 ..< 16) {
            state[i] = state[i] xor roundKey[i]
        }
    }

    /**
     * Rotate word
     * @param word: ByteArray
     */
    private fun rotWord(word: ByteArray) {
        val tmp = word.copyOf()
        word[0] = tmp[1]
        word[1] = tmp[2]
        word[2] = tmp[3]
        word[3] = tmp[0]
    }

    /**
     * Expand key
     */
    private fun keyExpansion() {
        val nk = keyLength.byteLength / 4
        val nb = 4
        val nr = nk + 6

        var i = 0
        val temp = ByteArray(4)
        var rcon = byteArrayOf(
            0x01.toByte(), 0x00.toByte(), 0x00.toByte(), 0x08.toByte()
        )
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

                rcon = rcon.copyOf(4)
                rcon[0] = gmul(rcon[0], 0x02)
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

    /**
     * Encrypt block
     * @param block: ByteArray
     */
    private fun encryptBlock( block: ByteArray ) {
        val nk = keyLength.byteLength / 4
        val nr = nk + 6
        val nb = 4
        val blockSize = nb * 4
        addRoundKey(
            block,
            keyExpanded.copyOfRange(0, blockSize)
        )

        for (round in 1..<nr) {
            subBytes(block)
            shiftRows(block)
            mixColumns(block)
            addRoundKey(
                block,
                keyExpanded.copyOfRange(round * nb, (round + 1) * blockSize)
            )
        }
        subBytes(block)
        shiftRows(block)
        addRoundKey(
            block,
            keyExpanded.copyOfRange(nr * nb, (nr + 1) * blockSize)
        )
    }

    /**
     * Decrypt block
     * @param block: ByteArray
     */
    private fun decryptBlock( block: ByteArray ) {
        val nk = keyLength.byteLength / 4
        val nr = nk + 6
        val nb = 4
        val blockSize = nb * 4
        addRoundKey(
            block,
            keyExpanded.copyOfRange(nr * nb, (nr + 1) * blockSize)
        )

        for (round in nr - 1 downTo 1) {
           invShiftRows(block)
           invSubBytes(block)
           addRoundKey(
               block,
               keyExpanded.copyOfRange(round * nb, (round + 1) * blockSize)
           )
           invMixColumns(block)
        }

        invShiftRows(block)
        invSubBytes(block)
        addRoundKey(
            block,
            keyExpanded.copyOfRange(0, blockSize)
        )
    }

    /**
     * Encrypt file
     * @param inputFile: String
     * @param outputFile: String
     */
    fun encryptFile(inputFile: String, outputFile: String) {
        try {
            val inputStream = FileInputStream(inputFile)
            val outputStream = FileOutputStream(outputFile)

            var iv = ByteArray(16)
            //random iv
            for (i in iv.indices) {
                iv[i] = (Math.random() * 256).toInt().toByte()
            }
            outputStream.write(iv)

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
            inputStream.close()
            outputStream.flush()
            outputStream.close()
        } catch (e: FileNotFoundException) {
            error = true
            errorMessage = "Cannot find input file"
        } catch (e: IOException) {
            error = true
            errorMessage = "Cannot write output file"
        } catch (e: IllegalArgumentException) {
            error = true
            errorMessage = "Invalid key"
        } catch (e: SecurityException) {
            error = true
            errorMessage = "Permission denied"
        } catch (e: Exception) {
            error = true
            errorMessage = "Unknown error"
            e.printStackTrace()
        }
    }

    /**
     * Decrypt file
     * @param inputFile: String
     * @param outputFile: String
     */
    fun decryptFile(inputFile: String, outputFile: String) {
        try {
            val inputStream = FileInputStream(inputFile)
            val tempStream = ByteArrayOutputStream() // Temporary stream to store decrypted data

            var iv = ByteArray(16)
            inputStream.read(iv)

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

            while (lastIndex >= 0 && decryptedData[lastIndex] == 0x00.toByte() ) {
                lastIndex--
            }


            val outputStream = FileOutputStream(outputFile)
            outputStream.write(decryptedData, 0, lastIndex + 1)
            tempStream.close()
            inputStream.close()
            outputStream.flush()
            outputStream.close()
        } catch (e: FileNotFoundException) {
            error = true
            errorMessage = "Cannot find input file"
        } catch (e: IOException) {
            error = true
            errorMessage = "Cannot write output file"
        } catch (e: IllegalArgumentException) {
            error = true
            errorMessage = "Invalid key"
        } catch (e: SecurityException) {
            error = true
            errorMessage = "Permission denied"
        } catch (e: Exception) {
            error = true
            errorMessage = "Unknown error"
            e.printStackTrace()
        }
    }

    fun getError(): String {
        if (!error) {
            error = false
            return "No error"
        }
        error = false
        return errorMessage
    }

    companion object {
        private val Sbox = byteArrayOf(
            0x63.toByte(), 0x7c.toByte(), 0x77.toByte(), 0x7b.toByte(), 0xf2.toByte(), 0x6b.toByte(), 0x6f.toByte(), 0xc5.toByte(), 0x30.toByte(), 0x01.toByte(), 0x67.toByte(), 0x2b.toByte(), 0xfe.toByte(), 0xd7.toByte(), 0xab.toByte(), 0x76.toByte(),
            0xca.toByte(), 0x82.toByte(), 0xc9.toByte(), 0x7d.toByte(), 0xfa.toByte(), 0x59.toByte(), 0x47.toByte(), 0xf0.toByte(), 0xad.toByte(), 0xd4.toByte(), 0xa2.toByte(), 0xaf.toByte(), 0x9c.toByte(), 0xa4.toByte(), 0x72.toByte(), 0xc0.toByte(),
            0xb7.toByte(), 0xfd.toByte(), 0x93.toByte(), 0x26.toByte(), 0x36.toByte(), 0x3f.toByte(), 0xf7.toByte(), 0xcc.toByte(), 0x34.toByte(), 0xa5.toByte(), 0xe5.toByte(), 0xf1.toByte(), 0x71.toByte(), 0xd8.toByte(), 0x31.toByte(), 0x15.toByte(),
            0x04.toByte(), 0xc7.toByte(), 0x23.toByte(), 0xc3.toByte(), 0x18.toByte(), 0x96.toByte(), 0x05.toByte(), 0x9a.toByte(), 0x07.toByte(), 0x12.toByte(), 0x80.toByte(), 0xe2.toByte(), 0xeb.toByte(), 0x27.toByte(), 0xb2.toByte(), 0x75.toByte(),
            0x09.toByte(), 0x83.toByte(), 0x2c.toByte(), 0x1a.toByte(), 0x1b.toByte(), 0x6e.toByte(), 0x5a.toByte(), 0xa0.toByte(), 0x52.toByte(), 0x3b.toByte(), 0xd6.toByte(), 0xb3.toByte(), 0x29.toByte(), 0xe3.toByte(), 0x2f.toByte(), 0x84.toByte(),
            0x53.toByte(), 0xd1.toByte(), 0x00.toByte(), 0xed.toByte(), 0x20.toByte(), 0xfc.toByte(), 0xb1.toByte(), 0x5b.toByte(), 0x6a.toByte(), 0xcb.toByte(), 0xbe.toByte(), 0x39.toByte(), 0x4a.toByte(), 0x4c.toByte(), 0x58.toByte(), 0xcf.toByte(),
            0xd0.toByte(), 0xef.toByte(), 0xaa.toByte(), 0xfb.toByte(), 0x43.toByte(), 0x4d.toByte(), 0x33.toByte(), 0x85.toByte(), 0x45.toByte(), 0xf9.toByte(), 0x02.toByte(), 0x7f.toByte(), 0x50.toByte(), 0x3c.toByte(), 0x9f.toByte(), 0xa8.toByte(),
            0x51.toByte(), 0xa3.toByte(), 0x40.toByte(), 0x8f.toByte(), 0x92.toByte(), 0x9d.toByte(), 0x38.toByte(), 0xf5.toByte(), 0xbc.toByte(), 0xb6.toByte(), 0xda.toByte(), 0x21.toByte(), 0x10.toByte(), 0xff.toByte(), 0xf3.toByte(), 0xd2.toByte(),
            0xcd.toByte(), 0x0c.toByte(), 0x13.toByte(), 0xec.toByte(), 0x5f.toByte(), 0x97.toByte(), 0x44.toByte(), 0x17.toByte(), 0xc4.toByte(), 0xa7.toByte(), 0x7e.toByte(), 0x3d.toByte(), 0x64.toByte(), 0x5d.toByte(), 0x19.toByte(), 0x73.toByte(),
            0x60.toByte(), 0x81.toByte(), 0x4f.toByte(), 0xdc.toByte(), 0x22.toByte(), 0x2a.toByte(), 0x90.toByte(), 0x88.toByte(), 0x46.toByte(), 0xee.toByte(), 0xb8.toByte(), 0x14.toByte(), 0xde.toByte(), 0x5e.toByte(), 0x0b.toByte(), 0xdb.toByte(),
            0xe0.toByte(), 0x32.toByte(), 0x3a.toByte(), 0x0a.toByte(), 0x49.toByte(), 0x06.toByte(), 0x24.toByte(), 0x5c.toByte(), 0xc2.toByte(), 0xd3.toByte(), 0xac.toByte(), 0x62.toByte(), 0x91.toByte(), 0x95.toByte(), 0xe4.toByte(), 0x79.toByte(),
            0xe7.toByte(), 0xc8.toByte(), 0x37.toByte(), 0x6d.toByte(), 0x8d.toByte(), 0xd5.toByte(), 0x4e.toByte(), 0xa9.toByte(), 0x6c.toByte(), 0x56.toByte(), 0xf4.toByte(), 0xea.toByte(), 0x65.toByte(), 0x7a.toByte(), 0xae.toByte(), 0x08.toByte(),
            0xba.toByte(), 0x78.toByte(), 0x25.toByte(), 0x2e.toByte(), 0x1c.toByte(), 0xa6.toByte(), 0xb4.toByte(), 0xc6.toByte(), 0xe8.toByte(), 0xdd.toByte(), 0x74.toByte(), 0x1f.toByte(), 0x4b.toByte(), 0xbd.toByte(), 0x8b.toByte(), 0x8a.toByte(),
            0x70.toByte(), 0x3e.toByte(), 0xb5.toByte(), 0x66.toByte(), 0x48.toByte(), 0x03.toByte(), 0xf6.toByte(), 0x0e.toByte(), 0x61.toByte(), 0x35.toByte(), 0x57.toByte(), 0xb9.toByte(), 0x86.toByte(), 0xc1.toByte(), 0x1d.toByte(), 0x9e.toByte(),
            0xe1.toByte(), 0xf8.toByte(), 0x98.toByte(), 0x11.toByte(), 0x69.toByte(), 0xd9.toByte(), 0x8e.toByte(), 0x94.toByte(), 0x9b.toByte(), 0x1e.toByte(), 0x87.toByte(), 0xe9.toByte(), 0xce.toByte(), 0x55.toByte(), 0x28.toByte(), 0xdf.toByte(),
            0x8c.toByte(), 0xa1.toByte(), 0x89.toByte(), 0x0d.toByte(), 0xbf.toByte(), 0xe6.toByte(), 0x42.toByte(), 0x68.toByte(), 0x41.toByte(), 0x99.toByte(), 0x2d.toByte(), 0x0f.toByte(), 0xb0.toByte(), 0x54.toByte(), 0xbb.toByte(), 0x16.toByte())
        private val InvSbox = byteArrayOf(
            0x52.toByte(), 0x09.toByte(), 0x6A.toByte(), 0xD5.toByte(), 0x30.toByte(), 0x36.toByte(), 0xA5.toByte(), 0x38.toByte(), 0xBF.toByte(), 0x40.toByte(), 0xA3.toByte(), 0x9E.toByte(), 0x81.toByte(), 0xF3.toByte(), 0xD7.toByte(), 0xFB.toByte(),
            0x7C.toByte(), 0xE3.toByte(), 0x39.toByte(), 0x82.toByte(), 0x9B.toByte(), 0x2F.toByte(), 0xFF.toByte(), 0x87.toByte(), 0x34.toByte(), 0x8E.toByte(), 0x43.toByte(), 0x44.toByte(), 0xC4.toByte(), 0xDE.toByte(), 0xE9.toByte(), 0xCB.toByte(),
            0x54.toByte(), 0x7B.toByte(), 0x94.toByte(), 0x32.toByte(), 0xA6.toByte(), 0xC2.toByte(), 0x23.toByte(), 0x3D.toByte(), 0xEE.toByte(), 0x4C.toByte(), 0x95.toByte(), 0x0B.toByte(), 0x42.toByte(), 0xFA.toByte(), 0xC3.toByte(), 0x4E.toByte(),
            0x08.toByte(), 0x2E.toByte(), 0xA1.toByte(), 0x66.toByte(), 0x28.toByte(), 0xD9.toByte(), 0x24.toByte(), 0xB2.toByte(), 0x76.toByte(), 0x5B.toByte(), 0xA2.toByte(), 0x49.toByte(), 0x6D.toByte(), 0x8B.toByte(), 0xD1.toByte(), 0x25.toByte(),
            0x72.toByte(), 0xF8.toByte(), 0xF6.toByte(), 0x64.toByte(), 0x86.toByte(), 0x68.toByte(), 0x98.toByte(), 0x16.toByte(), 0xD4.toByte(), 0xA4.toByte(), 0x5C.toByte(), 0xCC.toByte(), 0x5D.toByte(), 0x65.toByte(), 0xB6.toByte(), 0x92.toByte(),
            0x6C.toByte(), 0x70.toByte(), 0x48.toByte(), 0x50.toByte(), 0xFD.toByte(), 0xED.toByte(), 0xB9.toByte(), 0xDA.toByte(), 0x5E.toByte(), 0x15.toByte(), 0x46.toByte(), 0x57.toByte(), 0xA7.toByte(), 0x8D.toByte(), 0x9D.toByte(), 0x84.toByte(),
            0x90.toByte(), 0xD8.toByte(), 0xAB.toByte(), 0x00.toByte(), 0x8C.toByte(), 0xBC.toByte(), 0xD3.toByte(), 0x0A.toByte(), 0xF7.toByte(), 0xE4.toByte(), 0x58.toByte(), 0x05.toByte(), 0xB8.toByte(), 0xB3.toByte(), 0x45.toByte(), 0x06.toByte(),
            0xD0.toByte(), 0x2C.toByte(), 0x1E.toByte(), 0x8F.toByte(), 0xCA.toByte(), 0x3F.toByte(), 0x0F.toByte(), 0x02.toByte(), 0xC1.toByte(), 0xAF.toByte(), 0xBD.toByte(), 0x03.toByte(), 0x01.toByte(), 0x13.toByte(), 0x8A.toByte(), 0x6B.toByte(),
            0x3A.toByte(), 0x91.toByte(), 0x11.toByte(), 0x41.toByte(), 0x4F.toByte(), 0x67.toByte(), 0xDC.toByte(), 0xEA.toByte(), 0x97.toByte(), 0xF2.toByte(), 0xCF.toByte(), 0xCE.toByte(), 0xF0.toByte(), 0xB4.toByte(), 0xE6.toByte(), 0x73.toByte(),
            0x96.toByte(), 0xAC.toByte(), 0x74.toByte(), 0x22.toByte(), 0xE7.toByte(), 0xAD.toByte(), 0x35.toByte(), 0x85.toByte(), 0xE2.toByte(), 0xF9.toByte(), 0x37.toByte(), 0xE8.toByte(), 0x1C.toByte(), 0x75.toByte(), 0xDF.toByte(), 0x6E.toByte(),
            0x47.toByte(), 0xF1.toByte(), 0x1A.toByte(), 0x71.toByte(), 0x1D.toByte(), 0x29.toByte(), 0xC5.toByte(), 0x89.toByte(), 0x6F.toByte(), 0xB7.toByte(), 0x62.toByte(), 0x0E.toByte(), 0xAA.toByte(), 0x18.toByte(), 0xBE.toByte(), 0x1B.toByte(),
            0xFC.toByte(), 0x56.toByte(), 0x3E.toByte(), 0x4B.toByte(), 0xC6.toByte(), 0xD2.toByte(), 0x79.toByte(), 0x20.toByte(), 0x9A.toByte(), 0xDB.toByte(), 0xC0.toByte(), 0xFE.toByte(), 0x78.toByte(), 0xCD.toByte(), 0x5A.toByte(), 0xF4.toByte(),
            0x1F.toByte(), 0xDD.toByte(), 0xA8.toByte(), 0x33.toByte(), 0x88.toByte(), 0x07.toByte(), 0xC7.toByte(), 0x31.toByte(), 0xB1.toByte(), 0x12.toByte(), 0x10.toByte(), 0x59.toByte(), 0x27.toByte(), 0x80.toByte(), 0xEC.toByte(), 0x5F.toByte(),
            0x60.toByte(), 0x51.toByte(), 0x7F.toByte(), 0xA9.toByte(), 0x19.toByte(), 0xB5.toByte(), 0x4A.toByte(), 0x0D.toByte(), 0x2D.toByte(), 0xE5.toByte(), 0x7A.toByte(), 0x9F.toByte(), 0x93.toByte(), 0xC9.toByte(), 0x9C.toByte(), 0xEF.toByte(),
            0xA0.toByte(), 0xE0.toByte(), 0x3B.toByte(), 0x4D.toByte(), 0xAE.toByte(), 0x2A.toByte(), 0xF5.toByte(), 0xB0.toByte(), 0xC8.toByte(), 0xEB.toByte(), 0xBB.toByte(), 0x3C.toByte(), 0x83.toByte(), 0x53.toByte(), 0x99.toByte(), 0x61.toByte(),
            0x17.toByte(), 0x2B.toByte(), 0x04.toByte(), 0x7E.toByte(), 0xBA.toByte(), 0x77.toByte(), 0xD6.toByte(), 0x26.toByte(), 0xE1.toByte(), 0x69.toByte(), 0x14.toByte(), 0x63.toByte(), 0x55.toByte(), 0x21.toByte(), 0x0C.toByte(), 0x7D.toByte()
        )
    }
}