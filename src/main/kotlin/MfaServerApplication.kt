import controller.MfaController
import org.koin.standalone.StandAloneContext.startKoin

class MfaServerApplication {
    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            startKoin(listOf(mfaModule))
            MfaController(7000).startApplication()
        }
    }
}