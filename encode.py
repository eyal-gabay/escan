from urllib.parse import quote
from base64 import b64encode
import re
import html

all_the_payloads = []


def no_encode(payload):
    return payload


def unicode(payload: str):
    return str(re.sub('.', lambda x: r'\u % 04X' % ord(x.group()), payload)).replace(" ", "0").replace("u0", "u")


def url_encode(payload: str):
    return quote(payload)


def upper(payload: str):
    return payload.upper()


def html_entities(payload: str):
    return html.escape(payload)


def js_alert_encode(payload: str):
    a = ""
    for i in payload:
        e = str(re.sub('.', lambda x: r'%4X' % ord(x.group()), i)).strip()
        a += "&#" + ("00000000" + e)[len(e):]
    return a


def decimal_html(payload: str):
    a = ""
    for i in payload:
        e = str(re.sub('.', lambda x: r'%4X' % ord(x.group()), i)).strip()
        a += "&#" + e + ";"
    return a


def base_64(payload: str):
    return str(b64encode(bytes(payload, "utf-8")))[2:-1]


def encode(payload="\"'", mix=False, debug=False, nothing=True):
    if nothing:
        return [f"\"{payload}\""]
    if not mix:
        if debug:
            print(no_encode(payload))
            print(unicode(payload))
            print(url_encode(payload))
            print(upper(payload))
            print(html_entities(payload))
            print(js_alert_encode(payload))
            print(decimal_html(payload))
            print(base_64(payload))
        return [no_encode(payload), unicode(payload), url_encode(payload), upper(payload), html_entities(payload), js_alert_encode(payload), decimal_html(payload), base_64(payload)]
    else:
        after_encode = []
        after_encode_as_strings = []
        all_the_encoders = [no_encode, unicode, url_encode, upper, html_entities, js_alert_encode, decimal_html, base_64]
        all_the_encoders_with_payloads = [no_encode(payload), unicode(payload), url_encode(payload), upper(payload), html_entities(payload), js_alert_encode(payload), decimal_html(payload), base_64(payload)]
        for encoder in all_the_encoders:
            for par in all_the_encoders_with_payloads:
                after_encode.append(list(map(encoder, [par])))
        for i in after_encode:
            after_encode_as_strings.append(i[0])
        if debug:
            print(after_encode_as_strings)
        return after_encode_as_strings


def check_double(payload):
    if payload not in all_the_payloads:
        all_the_payloads.append(payload)
        return payload
    else:
        return False


if __name__ == '__main__':
    a = ""
    for i in encode():
        a += i
    print(a.replace("&", "%26").replace("#", "%23"))