import { verify } from './login'
import { decode } from './storekit2'
import { Service } from 'hub-service'
interface Login {
  token: string
  app: string
}
let address: string | undefined
const argv = process.argv.slice(2)
while (true) {
  const command = argv.shift()
  if (!command) break
  switch (command) {
    case '-p':
    case '--port':
      const port = Number(argv.shift())
      if (!isNaN(port)) address = `ws://localhost:${port}`
      break
    default:
      break
  }
}

new Service(address)
  .post('apple/login', (body: Login) => verify(body.token, body.app))
  .post('apple/login/lite', (body: Login) => verify(body.token, body.app).then(a => a?.sub))
  .post('apple/storekit2', decode)
  .start()
