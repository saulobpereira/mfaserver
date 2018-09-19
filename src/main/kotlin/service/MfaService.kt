package service

interface MfaService {
    fun validateToken(fingerprint: String, token: String): String
    fun generateSeed(fingerprint: String): String
}