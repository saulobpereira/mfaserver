package controller

import endpoint.TokenEndpoints
import io.javalin.Javalin
import org.koin.standalone.KoinComponent
import org.koin.standalone.inject
import service.MfaService

class MfaController(private val port: Int): KoinComponent {

    private val mfaService by inject<MfaService>()

    fun startAplication(): Javalin {
        val app = Javalin.create().apply {
            port(port)
            exception(Exception::class.java) { e, _ -> e.printStackTrace() }
        }.start()

        app.routes {
            TokenEndpoints(mfaService).addEndpoints()
        }
        return app
    }
}