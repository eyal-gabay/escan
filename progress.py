from termcolor import colored


def write_request(
        url: str,
        method: str,
        where: str,
        parameter: str,
        payload: str,
        request_status,
        status="",
        error="",
        dom=None,
):
    if request_status == "500":
        print(colored(
            f"[url: {url} | status: {request_status} | method: {method} | where: {where} | parameter: {parameter} "
            f"| payload: {payload}]", "yellow"))
    if status == "bad":
        print(colored(f"[url: {url} | status: {request_status} | method: {method} | where: {where} | parameter: {parameter} "
                      f"| payload: {payload}]", "red"))
    elif status == "warning":
        print(colored(f"[url: {url} | status: {request_status} | method: {method} | where: {where} | parameter: {parameter} "
                      f"| payload: {payload}]", "yellow"))
    elif status == "good":
        print(colored(f"[url: {url} | status: {request_status} | method: {method} | where: {where} | parameter: {parameter} "
                      f"| payload: {payload}]", "green"))
    if dom:
        print(colored(dom, "green"))
    if status == "error":
        print("error at", url)


