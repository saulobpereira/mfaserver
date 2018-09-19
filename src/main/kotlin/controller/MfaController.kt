package controller

import com.google.gson.GsonBuilder
import endpoint.SeedEndpoints
import endpoint.TokenEndpoints
import io.javalin.Javalin
import io.javalin.json.FromJsonMapper
import io.javalin.json.JavalinJson
import io.javalin.json.ToJsonMapper
import org.koin.standalone.KoinComponent
import org.koin.standalone.inject
import service.MfaService

class MfaController(private val port: Int): KoinComponent {

    private val mfaService by inject<MfaService>()

    fun startApplication(): Javalin {
        val app = Javalin.create().apply {
            port(port)
            exception(Exception::class.java) { e, _ -> e.printStackTrace() }
        }.start()

        configureJsonMapper()

        app.routes {
            TokenEndpoints(mfaService).addEndpoints()
            SeedEndpoints(mfaService).addEndpoints()
        }
        return app
    }

    private fun configureJsonMapper() {
        val gson = GsonBuilder().create()
        JavalinJson.fromJsonMapper = object : FromJsonMapper {
            override fun <T> map(json: String, targetClass: Class<T>): T = gson.fromJson(json, targetClass)
        }

        JavalinJson.toJsonMapper = object : ToJsonMapper {
            override fun map(obj: Any): String = gson.toJson(obj)
        }
    }
}