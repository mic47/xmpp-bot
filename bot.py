#!/usr/bin/python
import argparse
import functools
import re
import datetime
import json
import sys
import subprocess
import logging
from typing import Pattern, List, Tuple, Any, Callable, Iterable

import xmpp
from python_weather import Client, HTTPException
from asyncio import get_event_loop


_PATTERNS: List[Tuple[Pattern, Callable[[Any, Any, Any], str]]] = []


def handler(pattern: Pattern, pats=_PATTERNS):
    def decorator(func):
        pats.append((pattern, func))
        return func

    return decorator

authorized_users = set()

def handle_message(conn, mess):
    text = mess.getBody()
    x = str(mess.getFrom()).split("/", maxsplit=1)
    if len(x) == 1:
        user, client = x[0], ""
    else:
        user, client = x
    print(client)
    if user not in authorized_users:
        conn.send(xmpp.Message(mess.getFrom(), "Unauthorized"))
        return
    for pattern, func in _PATTERNS:
        match = pattern.match(text)
        if match is None:
            continue
        try:
            ret = func(conn, mess, match)
            conn.send(xmpp.Message(mess.getFrom(), ret))
        except Exception as e:
            logging.exception(f"Error while executing {text} from {user}")
            conn.send(xmpp.Message(mess.getFrom(), "Error while executing command: " + str(e)))
        return
    print(text)
    print(user)
    conn.send(xmpp.Message(mess.getFrom(), "Unknown command"))
    return


# TODO:
# Open link
# Bark detector
# Where is my dog
# Volume normalizng
# use this instead: https://lab.louiz.org/poezio/slixmpp


@handler(re.compile(r"https://.*", flags=re.I))
def open_link(conn, mess, match: re.Match) -> str:
    subprocess.run(["xdg-open", mess.getBody()], check=True)
    return "Link opened."


@handler(re.compile(r"where is my dog", flags=re.I))
def where_is_my_dog(conn, mess, match: re.Match) -> str:
    return "I don't know."

@handler(re.compile(r"restart", flags=re.I))
def restart(conn, mess, match: re.Match) -> str:
    sys.exit(0)


async def get_weather(location) -> str:
    weather_client = Client(format="C", locale="en-US")
    response = await weather_client.find(location)
    current = response.current
    unit = "C"
    wind = ""
    ws = current._get("@windspeed")
    if ws:
        wind = f", {ws} wind"
    output = {
        "Loc": f"{response.location_name} ({response.latitude}, {response.longitude})",
        "Temp": f"{current.temperature} °{unit} / {current.feels_like} °{unit}",
        "Weather": f"{current.sky_text}, {current.humidity}% humidity{wind}",
        "date": datetime.datetime.strftime(current.date, f"%A, %d %B %Y at %H:%M",),
    }

    for forecast in response.forecasts:
        formatted_date = datetime.datetime.strftime(forecast.date, f"%A, %d %B %Y",)
        output[
            formatted_date
        ] = f"low {forecast.low} °{unit}, high {forecast.high} °{unit}, {forecast.sky_text}, {(forecast.precip) or '0'}% rain"
    output["link"] = response.url
    return "\n".join(pp_json(output, 0))


def pp_json(data, indent) -> Iterable[str]:
    for k, v in data.items():
        if isinstance(v, str):
            yield " " * indent + f"*{k}*: {v}"
        elif isinstance(v, dict):
            yield " " * indent + "*" + k + "*" + ":"
            yield from pp_json(v, indent + 2)
        else:
            raise NotImplementedError(f"output type {type(v)}")


@handler(re.compile(r"geo:(?P<lat>[0-9.]*),(?P<lon>[0-9.]*)"))
def weather_location(conn, mess, match: re.Match) -> str:
    lat = float(match.group("lat"))
    lon = float(match.group("lon"))
    return get_event_loop().run_until_complete(get_weather(f"{lat}, {lon}"))


@handler(re.compile(r"weather (in|at) (?P<loc>.*)", flags=re.I))
def weather_at_location(conn, mess, match: re.Match) -> str:
    loc = match.group("loc")
    return get_event_loop().run_until_complete(get_weather(loc))


def try_process(conn):
    try:
        conn.Process(1)
    except KeyboardInterrupt:
        return 0
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--account")
    parser.add_argument("--password")
    parser.add_argument("--authorized-users", default="")
    return parser.parse_args()


def main():
    args = parse_args()
    jid = xmpp.JID(args.account)
    user, server, password = jid.getNode(), jid.getDomain(), args.password
    global authorized_users
    for x in args.authorized_users.split(","):
        authorized_users.add(x)

    conn = xmpp.Client(server)  # ,debug=[])
    conres = conn.connect()
    if not conres:
        print(f"Unable to connect to server {server}", file=sys.stderr)
        sys.exit(1)
    if conres != "tls":
        print("Warning: unable to estabilish secure connection - TLS failed!", file=sys.stderr)
    authres = conn.auth(user, password)
    if not authres:
        print(f"Unable to authorize on {server} - check login/password.", file=sys.stderr)
        sys.exit(1)
    if authres != "sasl":
        print(
            "Warning: unable to perform SASL auth os {server}. Old authentication method used!",
            file=sys.stderr,
        )
    print(conres, authres)
    conn.RegisterHandler("message", handle_message)  # type: ignore
    conn.sendInitPresence()
    print("Bot started.", file=sys.stderr)
    while try_process(conn):
        pass


if __name__ == "__main__":
    main()
