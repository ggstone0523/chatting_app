from aiohttp import web
import aiohttp
import aioredis
from aiohttp_cors import setup as cors_setup, ResourceOptions
import secrets


def create_json(status, state_msg):
    return {"state": status, "state_msg": state_msg}


async def login_handler(request):
    try:
        msg = await request.json()
        redis_password = await redis.get(msg["id"])
        if redis_password is None:
            return web.json_response(create_json("bad", "input value invalid"))
        if msg["password"] == redis_password.decode('ascii'):
            security_token = str(hash(secrets.token_hex(16) + msg["id"]))
            await redis.set(security_token, msg["id"])
            return web.json_response(create_json("ok", security_token))
        else:
            return web.json_response(create_json("bad", "input value invalid"))
    except Exception:
        return web.json_response(create_json("bad", "unknown fail"))


async def logon_handler(request):
    try:
        msg = await request.json()
        if await redis.get(msg["id"]) is not None:
            return web.json_response(create_json("bad", "input value invalid"))
        await redis.set(msg["id"], msg["password"])
        return web.json_response(create_json("ok", "success"))
    except Exception:
        return web.json_response(create_json("bad", "unknown fail"))


async def logout_handler(request):
    try:
        msg = await request.json()
        if await redis.delete(msg["security_token"]) == 1:
            return web.json_response(create_json("ok", "success"))
        else:
            return web.json_response(create_json("bad", "input value invalid"))
    except Exception:
        return web.json_response(create_json("bad", "unknown fail"))


async def delete_account_handler(request):
    try:
        msg = await request.json()
        redis_password = await redis.get(msg["id"])
        if redis_password is None:
            return web.json_response(create_json("bad", "input value invalid"))
        if msg["password"] != redis_password.decode('ascii'):
            return web.json_response(create_json("bad", "input value invalid"))
        if msg["security_token"] != "logout":
            await redis.delete(msg["security_token"])
        if await redis.delete(msg["id"]) == 1:
            return web.json_response(create_json("ok", "success"))
        else:
            return web.json_response(create_json("bad", "input value invalid"))
    except Exception:
        return web.json_response(create_json("bad", "unknown fail"))


async def check_security_token(ws_current):
    try:
        msg = await ws_current.receive()
        name = await redis.get(msg.data)
        if name is not None:
            return name.decode('ascii')
        else:
            return False
    except Exception:
        return False


async def shutdown(app):
    try:
        app_keys = list(app['websockets'].keys())
        for i in range(len(app_keys)):
            await app['websockets'][app_keys[i]].close()
        app['websockets'].clear()
    except Exception:
        pass


async def websocket_handler(request):
    try:
        ws_current = web.WebSocketResponse()
        await ws_current.prepare(request)

        name = await check_security_token(ws_current)
        if name is False:
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
    except Exception:
        pass

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
