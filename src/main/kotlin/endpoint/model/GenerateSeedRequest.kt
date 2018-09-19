package endpoint.model

import com.google.gson.annotations.SerializedName

data class GenerateSeedRequest(
        @SerializedName("fingerprint") val fingerprint: String
)