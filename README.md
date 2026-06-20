<h1>
  <img alt="Containerization logo" src="./icon.png" width="70" valign="middle">
  &nbsp;Login with Apple
</h1>

> Made for [Hub](https://hub.v57.dev)

Apple service allows you to verify Login with Apple and StoreKit2 transaction tokens without adding a all dependencies to your server, so it can stay lightweight. 

Run from multiple machines or multiple processes for better performance and uptime

Use Hub Launcher to easily scale it up, increasing number of running processes. As Bun/js/ts is a single core process

## Login with Apple

```ts
const request: Login
const userId: String = await service.send('apple/login/lite', request)
```
### Detailed login
```ts
const request: Login
const userInfo: any = await service.send('apple/login', request)
```
## Verify and Decode StoreKit2 transaction
```ts
const request: string
const transaction: any = await service.send('apple/storekit2', request)
```

## Types
```ts
interface Login {
  token: string
  app: string
}
```
