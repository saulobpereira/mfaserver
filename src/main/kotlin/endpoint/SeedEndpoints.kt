package endpoint

import endpoint.model.GenerateSeedRequest
import io.javalin.apibuilder.ApiBuilder.path
import io.javalin.apibuilder.ApiBuilder.post
import io.javalin.apibuilder.EndpointGroup
import service.MfaService

class SeedEndpoints (private val mfaService: MfaService): EndpointGroup {
    override fun addEndpoints() {
        path("seed") {
            post("generate") { ctx ->
                val request = ctx.bodyAsClass(GenerateSeedRequest::class.java)
                ctx.result(mfaService.generateSeed(request.fingerprint))
            }

        }
    }

}