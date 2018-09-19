import org.koin.dsl.module.module
import service.MfaService
import service.MfaServiceImpl

val mfaModule = module{
    single<MfaService> { MfaServiceImpl() }
}