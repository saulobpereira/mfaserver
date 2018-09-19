package endpoint

import io.javalin.apibuilder.ApiBuilder.*
import io.javalin.apibuilder.EndpointGroup
import service.MfaService

class TokenEndpoints(val mfaService: MfaService): EndpointGroup{
    override fun addEndpoints() {
        path("token") {
            post("validate") { ctx ->
                ctx.result(mfaService.validate().toString())
            }
            get("health") { ctx ->
                ctx.result("It is Ok")
            }
        }
    }

}