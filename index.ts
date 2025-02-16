import { verify } from './login'
import { Service } from 'hub-service'
interface Login {
  token: string
  app: string
}
new Service().post('apple/login', (body: Login) => verify(body.token, body.app)).start()
