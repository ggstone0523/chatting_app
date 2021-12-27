from aiohttp import web
import aiohttp
import aioredis
from aiohttp_cors import setup as cors_setup, ResourceOptions
import secrets
import time

async def login_handler(request):
    try:
        msg = await request.json()
        redis_password = await redis.get(msg["id"])
        if msg["password"] == redis_password.decode('ascii'):
            security_token = str(hash(secrets.token_hex(16) + msg["id"] + str(time.time())))
            await redis.set(security_token, msg["id"])
            return web.Response(text=security_token)
        else:
            return web.Response(text="password check failed")
    except:
        return web.Response(text="failed")

async def logon_handler(request):
    try:
        msg = await request.json()
        if await redis.get(msg["id"]) != None:
            return web.Response(text='id check failed')
        await redis.set(msg["id"], msg["password"])
        return web.Response(text="success")
    except:
        web.Response("failed")
    
async def logout_handler(request):
    try:
        msg = await request.json()
        if await redis.delete(msg["security_token"]) == 1:
            return web.Response(text="logout successed")
        else:
            return web.Response(text="security_token check failed")
    except:
        web.Response(text="failed")

async def delete_account_handler(request):
    try:
        msg = await request.json()
        redis_password = await redis.get(msg["id"])
        if msg["password"] != redis_password.decode('ascii'):
            return web.Response(text="password check failed")
        if msg["security_token"] != "logout":
            await redis.delete(msg["security_token"])
        if await redis.delete(msg["id"]) == 1:
            return web.Response(text="delete account success")
        else:
            return web.Response(text="delete account failed")
    except:
        web.Response(text="failed")

async def check_security_token(ws_current):
    try:
        msg = await ws_current.receive()
        name = await redis.get(msg.data)
        if name != None:
            return name.decode('ascii')
        else:
            return False
    except:
        return False

async def shutdown(app):
    app_keys = list(app['websockets'].keys())
    for i in range(len(app_keys)):
        await app['websockets'][app_keys[i]].close()
    app['websockets'].clear()

async def websocket_handler(request):
    ws_current = web.WebSocketResponse()
    await ws_current.prepare(request)

    name = await check_security_token(ws_current)
    if name == False:
        ws_current.close()
        return ws_current
    request.app['websockets'][name] = ws_current
    
    while True:
        msg = await ws_current.receive()

        if msg.type == aiohttp.WSMsgType.TEXT:
            for ws in request.app['websockets'].values():
                if ws is not ws_current:
                    await ws.send_str(name + ' : ' + msg.data)
            if msg.data == 'close':
                await ws_current.close()
                break
        else:
            break
    
    del request.app['websockets'][name]
    print('websocket connection closed')

    return ws_current

redis = aioredis.from_url("redis://redis:6379")
app = web.Application()
app.on_shutdown.append(shutdown)
app['websockets'] = {}
routes = [
    web.get('/ws', websocket_handler),
    web.post('/logon', logon_handler),
    web.post('/login', login_handler),
    web.post('/logout', logout_handler),
    web.post('/delete_account', delete_account_handler)
    ]
app.router.add_routes(routes)
cors = cors_setup(
    app,
    defaults={
        "*": ResourceOptions(
            allow_credentials=True, expose_headers="*", allow_headers="*",
        )
    },
)
for route in list(app.router.routes()):
    cors.add(route)
web.run_app(app)