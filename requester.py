from json.decoder import JSONDecodeError
from requests.exceptions import ConnectionError
from requests.exceptions import ProxyError
from requests.exceptions import ReadTimeout, ChunkedEncodingError
from selenium.common.exceptions import NoAlertPresentException

from tools.escan.dom_xss import dom_xss
from tools.escan.functions import json
from tools.escan.progress import write_request

from selenium import webdriver
from pyvirtualdisplay import Display
from time import sleep
import requests


es = "e" * 20
risk = "<>&\"'"
c = 1
c2 = 0
once = 0
all_the_things_i_found = []
double_payload = []
timeouts = 0
take_a_look_at = []
response_status = []


def verify(response, method, url, payload, parameter, where, sleep_time, show_progress):
    """chack the respones"""
    #############
    "  scaners  "
    #############
    response_status.append((response.status_code, url, parameter, payload, "get", where))
    dom_xss(response.text, payload, url)
    "now better.com"
    if response.status_code in [400]:
        if show_progress:
            write_request(url, method, where, parameter, payload, response.status_code, "bad")
        sleep(sleep_time)
        return False
    if es not in response.text:
        if show_progress:
            write_request(url, method, where, parameter, payload, response.status_code, "bad")
        sleep(sleep_time)
        return False
    ###############
    """ explore """
    ###############
    for i in risk:
        try:
            if i in response.text.split(es)[1].split(es)[0].replace("&#", "").replace("&quot;", "").replace("&gt;", "")\
                    .replace("&lt;", "").replace("&amp;", ""):
                if method == "GET":
                    if [url, parameter, payload, "get", where] not in all_the_things_i_found:
                        all_the_things_i_found.append([url, parameter, payload, "get", where])
                        if show_progress:
                            write_request(url, "get", where, parameter, payload, response.status_code, "good")
                else:
                    if [url, parameter, payload, "post", where] not in all_the_things_i_found:
                        all_the_things_i_found.append([url, parameter, payload, "post", where])
                        if show_progress:
                            write_request(url, "post", where, parameter, payload, response.status_code, "good")
                pass
        except IndexError:
            pass
    sleep(sleep_time)

    ##################
    "   check json   "
    ##################
    try:
        if response.json():
            for i in risk:
                try:
                    if i in response.json().split(es)[1].split(es)[0].replace("&#", "").replace("&quot;", "")\
                            .replace("&gt;", "").replace("&lt;", "").replace("&amp;", ""):
                        if [url, parameter, payload, "post", where] not in all_the_things_i_found:
                            all_the_things_i_found.append([url, parameter, payload, "post", where])
                except IndexError:
                    pass
    except JSONDecodeError:
        pass
    return True


def selenium(
        method: str,
        url: str,
        headers: dict,
        cookies,
        data,
        check_alert: bool,
        show_progress: bool,
        timeout=0.0,
        get_parameters=str,
        sleep_time=0,
        *payloads,
        proxy: dict,
        mime_type="",
        json_parameters=None
):
    """
    selenium
    open the request in browser and check if alerted
    """
    display = Display(visible=0, size=(800, 800))
    display.start()

    browser = webdriver.Firefox(service_log_path="/dev/null")

    def new_selenium_requester(request):
        for k, v in headers.items():
            print(k, v)
            del request.headers[k]
            request.headers[k] = v

    if method == "GET":
        cookies = {"name": "python", "value": "t"}
        browser.add_cookie(cookies)
        browser.request_interceptor = new_selenium_requester
        browser.get(url)
        try:
            browser.switch_to_alert().accept()
            print("alert", url)
        except NoAlertPresentException:
            print("no alert", url)
    browser.close()
    

def requester(
        method: str,
        url: str,
        headers: dict,
        cookies,
        data,
        check_alert: bool,
        show_progress: bool,
        timeout=0.0,
        get_parameters=str,
        sleep_time=0,
        *payloads,
        proxy: dict,
        mime_type="",
        json_parameters=None,
        check_just_if_he_has_parameters=False,
        check_on_cookies=False
):
    """
    1: make the request
    2: send the request and take the response
    3: send the response to verify

    + requests error handling
    """
    # if method == "GET":
    #     return
    if check_just_if_he_has_parameters and not data and get_parameters != "?":
        return
    global timeouts
    if not cookies:
        cookies = {}
    " added now 'better.com'"
    cookies["better-session"] = "%7B%22authenticated%22%3A%7B%22authenticator%22%3A%22authenticator%3Acustom%22%2C%22sessionId%22%3A%22iEi87jNfqHvxSVg2kkHSEv9frZ4yD50OXEnRuCf%2F4a7rqZt6T5nG0%2BYt1qsCYuXwKoTNlssqspWC5tlrx2AtXXPWQeMiH9QetkBn1KU5pJ8VFO7V9l8rMozdl%2BmI748FoDozMvSrUKFks%2FemPeAZMjBrLPQkjkCLHlAiipMMLUfz8Hel%2BHcrMD6%2BXP2STxj%2FaXr4QAO0iCg6EBM%2BP44Sb%2Bsgh96cdvdVhaP%2BNV%2Fu6nNNrTNSaX%2BvORBEL%2BJi%2F3D3fiFkla30cSqM2tasQaI0LhiNA2eznJGQtLt7I5KrLwsJ25QPLwa7qXdD0pIoE8x6GrlyvWUDWZKtA76rf3SOrOxZLb96IViHvurNyVggPQoUV7dTkUEInlGdb0FxQC%2FnmjpL7ZeTGyoIaMbIPhEqG33h0AHGUXuxU%2F9VE33X1PSHtxWl994qODGbuSxJrcTxLi8K7mK4hfGSrCXPk2dhqC425VtFVGHpHEfOnUtMBpXDaC8U3boPXN%2BSxNvBxKf8%22%2C%22creationTimestamp%22%3A1619380468562%2C%22expiresMs%22%3A86400000%2C%22expiresTimestamp%22%3A1619466868562%2C%22isAdmin%22%3Afalse%2C%22email%22%3A%22eyyalgabay%40gmail.com%22%2C%22userId%22%3A1768324%2C%22accountUuid%22%3A%2227ba468c-93be-47e6-8e45-4fe002224ef9%22%7D%7D"
    if not data:
        data = {}
    if get_parameters != "?":
        pars = str(get_parameters).replace("#", "%23")
    else:
        pars = ""

    param = []
    value = []
    try:
        for var in pars.split("&"):
            param.append(var.split("=")[0])
            value.append(var.split("=")[1])
    except IndexError:
        pass
    finally:
        all_get_parameters = list(zip(param, value))
    s = requests.Session()
    for i in cookies.keys():
        if "csrf" in i:
            csrf = str(s.get(url).cookies[i])
            cookies[i.strip()] = csrf.strip()
    # for payload in progressbar(payloads[0], prefix=url.split("?")[0] + ': ', suffix='Complete', length=50):
    if method == "GET":
        try:
            for x, y in all_get_parameters:
                for payload in payloads[0]:
                    r = s.get(
                        url.split("?")[0],
                        headers=headers,
                        cookies=cookies,
                        data=data,
                        params=pars.split("?")[1].replace(y, es + payload + es),
                        timeout=timeout,
                        proxies=proxy
                    )
                    if not verify(r, method, url, payload, y, "get_parameter", sleep_time, show_progress):
                        break
        except ProxyError:
            print("proxy error :(")
            exit()
        except ConnectionError as error:
            for u, e in take_a_look_at:
                if url == u:
                    continue
                take_a_look_at.append((url, error))
        except ReadTimeout:
            timeouts += 1
        ##################
        "    cookies     "
        ##################
        if check_on_cookies:
            if pars:
                pars2 = pars.split("?")[1]
            else:
                pars2 = pars
            for i in range(len(cookies)):
                for payload in payloads[0]:
                    try:
                        w = cookies.copy()
                        parameter = list(w.keys())[i]
                        w[parameter] = str(f"{es}{payload}{es}".encode("utf-8"))[2:-1]
                    except AttributeError:
                        continue
                    try:
                        r = s.get(
                            url,
                            headers=headers,
                            cookies=w,
                            params=pars2,
                            timeout=timeout,
                            proxies=proxy,
                        )
                        if not verify(r, method, url, payload, parameter, "cookie", sleep_time, show_progress):
                            break
                    except ProxyError:
                        print("proxy error :(")
                        exit()
                    except ConnectionError as error:
                        if (url, error) not in take_a_look_at:
                            take_a_look_at.append((url, error))
                    except ChunkedEncodingError:
                        pass
                    except ReadTimeout:
                        timeouts += 1

    elif method == "POST":
        if mime_type == "json":
            for payload in payloads[0]:
                for w, parameter in json(json_parameters, payload):
                    try:
                        r = s.post(
                            url,
                            headers=headers,
                            cookies=cookies,
                            data=str(w.encode("utf-8"))[2:-1],
                            timeout=timeout,
                            allow_redirects=False,
                            proxies=proxy,
                        )
                        if not verify(r, method, url, payload, parameter, "post_parameter", sleep_time, show_progress):
                            b = True
                            break
                    except ProxyError:
                        print("proxy error :(")
                        exit()
                    except ConnectionError as error:
                        take_a_look_at.append((url, error))
                    except ReadTimeout:
                        timeouts += 1
                # print(payload)
                break
        else:
            for i in range(len(data)):
                for payload in payloads[0]:
                    try:
                        w = data.copy()
                        parameter = list(w.keys())[i]
                        payload = str(payload.encode("utf-8"))[2:-1]
                        w[parameter] = f"{es}{payload}{es}"
                    except AttributeError:
                        continue
                    try:
                        r = s.post(
                            url,
                            headers=headers,
                            cookies=cookies,
                            data=w,
                            timeout=timeout,
                            allow_redirects=False,
                            proxies=proxy,
                        )
                        if not verify(r, method, url, payload, parameter, "post_parameter", sleep_time, show_progress):
                            break
                    except ProxyError:
                        print("proxy error :(")
                        exit()
                    except ConnectionError as error:
                        take_a_look_at.append((url, error))
                    except ReadTimeout:
                        timeouts += 1

                ##################
                "    cookies     "
                ##################
                if check_on_cookies:
                    for coo in range(len(cookies)):
                        for payload in payloads[0]:
                            try:
                                w = cookies.copy()
                                parameter = list(w.keys())[coo]
                                payload = str(payload.encode("utf-8"))[2:-1]
                                w[parameter] = f"{es}{payload}{es}"
                            except AttributeError:
                                continue
                            try:
                                r = s.post(
                                    url,
                                    headers=headers,
                                    cookies=w,
                                    data=data,
                                    timeout=timeout,
                                    allow_redirects=False,
                                    proxies=proxy,
                                )
                                if not verify(r, method, url, payload, parameter, "cookie", sleep_time, show_progress):
                                    break
                            except ProxyError:
                                print("proxy error :(")
                                exit()
                            except ConnectionError as error:
                                if (url, error) not in take_a_look_at:
                                    # write_request(url, "", "", "", "", "error", error)
                                    take_a_look_at.append((url, error))
                            except ReadTimeout:
                                timeouts += 1
    global c
    c += 1


if __name__ == '__main__':
    __import__("os").system("python3 escan.py")
