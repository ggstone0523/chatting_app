from aiohttp import web
import aiohttp
import aioredis
from aiohttp_cors import setup as cors_setup, ResourceOptions
import secrets


def create_json(status: str, state_msg: str) -> dict:
    """
    JSON형식의 값을 보낼 수 있게끔 데이터를 받아서 dict 형식으로 변환시키는 함수

    Parameters
    ----------
    status : str
        응답의 상태 값
    state_msg : str
        응답의 상태 메시지

    Returns
    -------
    dict
        JSON 형식으로 값을 보낼 수 있도록 dict형식의 값을 반환
    """
    return {"state": status, "state_msg": state_msg}


async def login_handler(request):
    """
    사용자의 로그인을 처리하는 함수

    Parameters
    ----------
    request : object
        클라이언트에서 보내온 요청 정보

    Returns
    -------
    object
        로그인에 성공했을 시 보안 토큰을 클라이언트에게 반환,
        로그인에 실패했을 시 실패 메시지를 클라이언트에게 반환
    """
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
    """
    사용자의 가입을 처리하는 함수

    Parameters
    ----------
    request : object
        클라이언트에서 보내온 요청 정보

    Returns
    -------
    object
        가입에 성공했을 시 성공 메시지를 클라이언트에게 반환,
        가입에 실패했을 시 실패 메시지를 클라이언트에게 반환
    """
    try:
        msg = await request.json()
        if await redis.get(msg["id"]) is not None:
            return web.json_response(create_json("bad", "input value invalid"))
        await redis.set(msg["id"], msg["password"])
        return web.json_response(create_json("ok", "success"))
    except Exception:
        return web.json_response(create_json("bad", "unknown fail"))


async def logout_handler(request):
    """
    사용자의 로그아웃을 처리하는 함수

    Parameters
    ----------
    request : object
        클라이언트에서 보내온 요청 정보

    Returns
    -------
    object
        로그아웃에 성공했을 시 성공 메시지를 클라이언트에게 반환,
        로그아웃에 실패했을 시 실패 메시지를 클라이언트에게 반환
    """
    try:
        msg = await request.json()
        if await redis.delete(msg["security_token"]) == 1:
            return web.json_response(create_json("ok", "success"))
        else:
            return web.json_response(create_json("bad", "input value invalid"))
    except Exception:
        return web.json_response(create_json("bad", "unknown fail"))


async def delete_account_handler(request):
    """
    사용자의 계정삭제를 처리하는 함수

    Parameters
    ----------
    request : object
        클라이언트에서 보내온 요청 정보

    Returns
    -------
    object
        계정삭제에 성공했을 시 성공 메시지를 클라이언트에게 반환,
        계정삭제에 실패했을 시 실패 메시지를 클라이언트에게 반환
    """
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


async def shutdown(app):
    """
    ws연결을 담당하는 서버가 갑작스럽게 종료할 시 이를 처리하는 함수

    Parameters
    ----------
    app : object
        클라이언트와의 websocket 연결상태를 저장하고 있는 객체

    Returns
    -------
    None
    """
    try:
        app_keys = list(app['websockets'].keys())
        for i in range(len(app_keys)):
            await app['websockets'][app_keys[i]].close()
        app['websockets'].clear()
    except Exception:
        pass


async def check_security_token(ws_current):
    """
    사용자로부터 보안 토큰을 받아 보안 토큰의 유효성을 확인해주는 함수

    Parameters
    ----------
    ws_current : object
        단일 클라이언트와의 websocket 연결상태를 저장하고 있는 객체

    Returns
    -------
    str
        보안 토큰이 알맞은 것일 경우 보안 토큰을 발급받은 사용자의 아이디를 반환,
        보안 토큰이 알맞지 않은 것일 경우 False 문자열을 반환
    """
    try:
        msg = await ws_current.receive()
        name = await redis.get(msg.data)
        if name is not None:
            return name.decode('ascii')
        else:
            return "False"
    except Exception:
        return "False"


async def send_old_message(ws_current):
    """
    redis에 저장되어있는 타 사용자들이 작성한 채팅 메시지들을
    채팅방에 처음 접속한 사용자에게 전송하는 함수.

    Parameters
    ----------
    ws_current : object
        단일 클라이언트와의 websocket 연결상태를 저장하고 있는 객체

    Returns
    -------
    None
    """
    try:
        msglist = await redis.lrange("msglist", 0, -1)
        msgliststrs = ""
        for i in range(len(msglist)):
            if i != len(msglist) - 1:
                msgliststrs = msgliststrs + msglist[i].decode('ascii') + '\n'
            else:
                msgliststrs = msgliststrs + msglist[i].decode('ascii')
        await ws_current.send_str(msgliststrs)
    except Exception:
        pass


async def websocket_handler(request):
    """
    websocket 연결 요청 핸들링 및
    한 클라이언트로부터 받은 메시지를 그 클라이언트와 같은 방에 있는
    모든 클라이언트에게 전달하는 함수

    Parameters
    ----------
    request : object
        클라이언트에서 보내온 요청 정보

    Returns
    -------
    object
        단일 클라이언트와의 websocket 연결상태를 저장하고 있는 객체를 반환
    """
    try:
        ws_current = web.WebSocketResponse()
        await ws_current.prepare(request)

        name = await check_security_token(ws_current)
        if name == "False":
            ws_current.close()
            return ws_current
        request.app['websockets'][name] = ws_current

        if await redis.llen("msglist") != 0:
            await send_old_message(ws_current)

        while True:
            msg = await ws_current.receive()
            msg_modified = name + ' : ' + msg.data

            if msg.type == aiohttp.WSMsgType.TEXT:
                for ws in request.app['websockets'].values():
                    if ws is not ws_current:
                        await ws.send_str(msg_modified)
                await redis.rpush("msglist", msg_modified)
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


def app_route_config():
    """
    사용자의 요청 종류에 따라 알맞은 핸들링을 할 수 있도록 라우팅을 해 주는 함수

    Parameters
    ----------
    None

    Returns
    -------
    None
    """
    try:
        app['websockets'] = {}
        routes = [
            web.get('/ws', websocket_handler),
            web.post('/logon', logon_handler),
            web.post('/login', login_handler),
            web.post('/logout', logout_handler),
            web.post('/delete_account', delete_account_handler)
        ]
        app.router.add_routes(routes)
    except Exception:
        pass


def app_cors_config():
    """
    CORS설정을 해 주는 함수

    Parameters
    ----------
    None

    Returns
    -------
    None
    """
    try:
        cors = cors_setup(
            app,
            defaults={
                "*": ResourceOptions(
                    allow_credentials=True,
                    expose_headers="*",
                    allow_headers="*",
                )
            },
        )
        for route in list(app.router.routes()):
            cors.add(route)
    except Exception:
        pass


redis = aioredis.from_url("redis://redis:6379")
app = web.Application()
app.on_shutdown.append(shutdown)
app_route_config()
app_cors_config()
web.run_app(app)
