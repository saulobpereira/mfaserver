package service.totp
/**
Copyright (c) 2011 IETF Trust and the persons identified as
authors of the code. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, is permitted pursuant to, and subject to the license
terms contained in, the Simplified BSD License set forth in Section
4.c of the IETF Trust's Legal Provisions Relating to IETF Documents
(http://trustee.ietf.org/license-info).
 */
import java.lang.reflect.UndeclaredThrowableException
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.text.SimpleDateFormat
import java.time.Instant
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and

/**
 * This is an example implementation of the OATH
 * TOTP algorithm.
 * Visit www.openauthentication.org for more information.
 *
 * @author Johan Rydell, PortWise, Inc.
 */
object TOTP {

    /**
     * This method uses the JCE to provide the crypto algorithm.
     * HMAC computes a Hashed Message Authentication Code with the
     * crypto hash algorithm as a parameter.
     *
     * @param crypto: the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
     * @param keyBytes: the bytes to use for the HMAC key
     * @param text: the message or text to be authenticated
     */
    private fun hmac_sha(crypto: String, keyBytes: ByteArray, text: ByteArray): ByteArray {
        try {
            val macKey = SecretKeySpec(keyBytes, "RAW")
            val hmac = Mac.getInstance(crypto)
            hmac.init(macKey)
            return hmac.doFinal(text)
        } catch (gse: GeneralSecurityException) {
            throw UndeclaredThrowableException(gse)
        }
    }

    /**
     * This method converts a HEX string to Byte[]
     *
     * @param hex: the HEX string
     *
     * @return: a byte array
     */
    private fun hexStr2Bytes(hex: String): ByteArray {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        val bArray = BigInteger("10$hex", 16).toByteArray()

        // Copy all the REAL bytes, not the "first"
        val ret = ByteArray(bArray.size - 1)
        for (i in ret.indices)
            ret[i] = bArray[i + 1]
        return ret
    }

    //                                    0  1   2    3     4      5       6        7         8
    private val DIGITS_POWER = intArrayOf(1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000)

    /**
     * This method generates a TOTP value for the given
     * set of parameters.
     *
     * @param seed: the shared secret, HEX encoded
     * @param time: a value that reflects a time
     * @param returnDigits: number of digits to return
     * @param crypto: the crypto function to use (HmacSHA1, HmacSHA256, HmacSHA512)
     *
     * @return: a numeric String in base 10 that includes
     * [truncationDigits] digits
     */
    @JvmOverloads
    fun generateTOTP(seed: String, time: Long = System.currentTimeMillis(), returnDigits: String = "8", crypto: String = "HmacSHA1"): String {
        val codeDigits = Integer.decode(returnDigits)!!.toInt()
        var result: String? = null

        val msgTime = ByteArray(8)
        var value = time

        // Converting the instant of time from the long representation to a
        // big-endian array of bytes (RFC4226, 5.2. Description).
        var i = 8
        while (i-- > 0) {
            msgTime[i] = value.toByte()
            value = value ushr 8
        }

        // Get the HEX in a Byte[]
        val sharedKey = hexStr2Bytes(seed)
        val hash = hmac_sha(crypto, sharedKey, msgTime)

        // put selected bytes into result int
        val offset = (hash[hash.size - 1] and 0xf).toInt()

        val binary =
                ((hash[offset    ].toInt() and 0x7f) shl 24) or
                        ((hash[offset + 1].toInt() and 0xff) shl 16) or
                        ((hash[offset + 2].toInt() and 0xff) shl 8 ) or
                        ((hash[offset + 3].toInt() and 0xff))

        val otp = binary % DIGITS_POWER[codeDigits]

        result = Integer.toString(otp)
        while (result!!.length < codeDigits) {
            result = "0$result"
        }
        return result
    }

    /**
     * This method verify a TOTP value.
     *
     * @param totp: the TOTP token
     * @param seed: the shared secret, HEX encoded
     * @param time: a value that reflects a time
     * @param returnDigits: number of digits to return
     * @param crypto: the crypto function to use (HmacSHA1, HmacSHA256, HmacSHA512)
     *
     * @return: a boolean result of the validation
     */
    fun isValidTOTP(totp: String, key: String, time: Long = System.currentTimeMillis(), returnDigits: String = "8", crypto: String = "HmacSHA1"): Boolean {
        return totp == generateTOTP(key, time, returnDigits, crypto)
    }

    @JvmStatic
    fun main(args: Array<String>) {
        // Seed for HMAC-SHA1 - 20 bytes
        val seed =
                "3132333435363738393031323334353637383930"
        // Seed for HMAC-SHA256 - 32 bytes
        val seed32 =
                "3132333435363738393031323334353637383930" +
                        "313233343536373839303132"
        // Seed for HMAC-SHA512 - 64 bytes
        val seed64 =
                "3132333435363738393031323334353637383930" +
                        "3132333435363738393031323334353637383930" +
                        "3132333435363738393031323334353637383930" +
                        "31323334"

        val initialTime: Long = 0
        val sizeStepTime: Long = 30
        val testTime = longArrayOf(
                59L, 1111111109L, 1111111111L,
                1234567890L, 2000000000L, 20000000000L
        )

        val simpleDateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
        simpleDateFormat.timeZone = TimeZone.getTimeZone("UTC")

        try {
            println("+---------------+-----------------------+--------------------+------------+----------+")
            println("|  Time(sec)    |   Time (UTC format)   |  Value of T(Hex)   |    TOTP    |  Mode    |")
            println("+---------------+-----------------------+--------------------+------------+----------+")

            for (i in testTime.indices) {
                val stepTime = (testTime[i] - initialTime) / sizeStepTime

                val fmtTime = testTime[i].toString().padEnd(11)
                val utcTime = simpleDateFormat.format(Date(testTime[i] * 1000))
                val fmtStepTime = stepTime.toString(16).padStart(16, '0').toUpperCase()

                println("|  $fmtTime  |  $utcTime  |  $fmtStepTime  |  ${generateTOTP(seed,   stepTime, "8", "HmacSHA1"  )}  |  SHA1    |")
                println("|  $fmtTime  |  $utcTime  |  $fmtStepTime  |  ${generateTOTP(seed32, stepTime, "8", "HmacSHA256")}  |  SHA256  |")
                println("|  $fmtTime  |  $utcTime  |  $fmtStepTime  |  ${generateTOTP(seed64, stepTime, "8", "HmacSHA512")}  |  SHA512  |")

                println("+---------------+-----------------------+--------------------+------------+----------+")
            }
        } catch (e: Exception) {
            println("Error : $e")
        }
    }
}