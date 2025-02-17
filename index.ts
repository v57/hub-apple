import { verify } from './login'
import { decode } from './storekit2'
import { Service } from 'hub-service'
interface Login {
  token: string
  app: string
}
new Service()
  .post('apple/login', (body: Login) => verify(body.token, body.app))
  .post('apple/login/lite', (body: Login) => verify(body.token, body.app).then(a => a?.sub))
  .post('apple/storekit2', decode)
  .start()
