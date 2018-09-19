package endpoint.model

import com.google.gson.annotations.SerializedName

data class ValidateTokenRequest(
        @SerializedName("fingerprint") val fingerprint: String,
        @SerializedName("token") val token: String
)