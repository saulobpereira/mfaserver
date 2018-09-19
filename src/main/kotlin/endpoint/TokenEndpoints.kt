package endpoint

import endpoint.model.ValidateTokenRequest
import io.javalin.apibuilder.ApiBuilder.*
import io.javalin.apibuilder.EndpointGroup
import service.MfaService

class TokenEndpoints(private val mfaService: MfaService): EndpointGroup{
    override fun addEndpoints() {
        path("token") {
            post("validate") { ctx ->
                val request = ctx.bodyAsClass(ValidateTokenRequest::class.java)
                ctx.result(mfaService.validateToken(request.fingerprint, request.token))
            }
            get("health") { ctx ->
                ctx.result("It is Ok")
            }
        }
    }

}