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
     * @param key: the shared secret, HEX encoded
     * @param time: a value that reflects a time
     * @param returnDigits: number of digits to return
     * @param crypto: the crypto function to use (HmacSHA1, HmacSHA256, HmacSHA512)
     *
     * @return: a numeric String in base 10 that includes
     * [truncationDigits] digits
     */
    @JvmOverloads
    fun generateTOTP(key: String, time: String, returnDigits: String, crypto: String = "HmacSHA1"): String {
        var time = time
        val codeDigits = Integer.decode(returnDigits)!!.toInt()
        var result: String? = null

        // Using the counter
        // First 8 bytes are for the movingFactor
        // Compliant with base RFC 4226 (HOTP)
        while (time.length < 16)
            time = "0$time"

        // Get the HEX in a Byte[]
        val msg = hexStr2Bytes(time)
        val k = hexStr2Bytes(key)
        val hash = hmac_sha(crypto, k, msg)

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

        val T0: Long = 0
        val X: Long = 30
        val testTime = longArrayOf(
                59L, 1111111109L, 1111111111L,
                1234567890L, 2000000000L, 20000000000L
        )

        var steps = "0"
        val df = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
        df.timeZone = TimeZone.getTimeZone("UTC")

        try {
            println("+---------------+-----------------------+------------------+----------+--------+")
            println("|  Time(sec)    |   Time (UTC format)   | Value of T(Hex)  |   TOTP   | Mode   |")
            println("+---------------+-----------------------+------------------+----------+--------+")

            for (i in testTime.indices) {
                val T = (testTime[i] - T0) / X

                steps = java.lang.Long.toHexString(T).toUpperCase()
                while (steps.length < 16) steps = "0$steps"

                val fmtTime = String.format("%1$-11s", testTime[i])
                val utcTime = df.format(Date(testTime[i] * 1000))

                println("|  $fmtTime  |  $utcTime  | $steps | ${generateTOTP(seed,   steps, "8", "HmacSHA1"  )} | SHA1   |")
                println("|  $fmtTime  |  $utcTime  | $steps | ${generateTOTP(seed32, steps, "8", "HmacSHA256")} | SHA256 |")
                println("|  $fmtTime  |  $utcTime  | $steps | ${generateTOTP(seed64, steps, "8", "HmacSHA512")} | SHA512 |")

                println("+---------------+-----------------------+------------------+----------+--------+")
            }
        } catch (e: Exception) {
            println("Error : $e")
        }
    }
}