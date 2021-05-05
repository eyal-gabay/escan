from requests.exceptions import ConnectionError

from tools.escan.dom_xss import all_the_dom_xss_i_found
from tools.escan.burp_to_python import burp_to_python
from tools.escan.encode import encode
from tools.escan.functions import reverse_replace
from tools.escan.requester import (all_the_things_i_found, take_a_look_at, requester, selenium, response_status,
                                   timeouts as final_timeouts)

from urllib.parse import urlparse
from base64 import b64decode
from random import random
from sys import argv
import argparse
import requests
import ast
import os


##############
"  settings  "
##############
if len(argv) < 2:
    ############
    " no flags "
    ############
    debug = False
    burp_xml_file = "xml_files/better.com.xml"
    write_to_file = True
    file_name = "scans/better_new.txt"
    sleep_time = 0.3
    requests_timeout = 3
    mix = False
    show_progress = True
    add_payloads_from_file = True
    payloads_file = "wordlists/sql.txt"  # "wordlists/big_xss_payload.txt"
    check_on_cookies = True
    show_banner = True
    proxy = False
    blind_xss = False
    check_alert = False
    check_just_if_he_has_parameters = False
    remove_files_end = ".js"
    if proxy:
        proxy_ip = "http://127.0.0.1:8080"
    else:
        proxy_ip = ""

    if blind_xss:
        my_ip = "http://127.0.0.1/"
    else:
        my_ip = ""
else:
    ###########
    "  flags  "
    ###########
    flags = argparse.ArgumentParser("find xss vulnerabilities in websites",
                                    epilog="""example:
                                    python3 escan.py --xml_file burp_xml_file.xml -f xss_payloads.txt --mix""")

    flags.add_argument("-p", action="store", help="proxy: https://127.0.0.1:8080", dest="proxy")
    flags.add_argument("--banner", action="store_false", help="dont show banner", default=True)
    flags.add_argument("-f", action='store', help="payloads file name")
    flags.add_argument("-s", action="store", type=float, help="add sleep between the requests", dest="sleep_time", default=0)
    flags.add_argument("--xml_file", action="store", type=str, help="xml file to read", required=True)
    flags.add_argument("-t", action="store", type=float, help="time out, default is 5", default=5, dest="timeout")
    flags.add_argument("--mix", action='store_true', help="encode the payload to bypass waf")
    flags.add_argument("--debug", action='store_true', help="see more stuff")
    flags.add_argument("-sp", action='store_true', help="show progress", dest="show_progress")
    flags.add_argument("-w", action='store', help="write to file", dest="file_name")
    flags.add_argument("--check", action='store_true', help="check if alerted", dest="check_alert")

    args = flags.parse_args()

    debug = args.debug
    burp_xml_file = args.xml_file
    sleep_time = args.sleep_time
    requests_timeout = args.timeout
    mix = args.mix
    show_progress = args.show_progress
    show_banner = args.banner
    blind_xss = False
    check_alert = args.check_alert
    if args.f:
        add_ = True
        add_payloads_from_file = args.f
    else:
        add_payloads_from_file = False
    if args.file_name:
        write_to_file = True
        file_name = args.file_name
    else:
        write_to_file = False
    if args.proxy:
        proxy_ip = args.proxy
        proxy = True
    else:
        proxy = False


if show_banner:
    print("""
    -------------------------------------------------------------------------------------------------------------
    eeeeeeee      y       y             a             l             x               x    ssssssssss    ssssssssss
    e              y     y             a a            l               x           x      s             s         
    e                y  y             a   a           l                 x       x        s             s         
    e                  y             aaaaaaa          l                   x   x          s             s         
    eeeeeeee          y             a       a         l                     x            ssssssssss    ssssssssss
    e                y             a         a        l                   x   x                   s             s
    e               y             a           a       l                 x       x                 s             s
    e              y             a             a      l               x           x               s             s
    eeeeeeee      y             a               a     l              x              x    ssssssssss    ssssssssss
    -------------------------------------------------------------------------------------------------------------
    
    """)


all_blind_xss_payloads = []
all_the_xss_payloads = []  # "<img src=X onerror=\"alert(1)\">"
double = []
status_count = []
result = []


def dub_files():
    if os.path.isfile(file_name):
        n = 1
        while 1:
            new_file_name = file_name + str(n)
            if os.path.isfile(new_file_name):
                n += 1
            else:
                break


def write_to_file_funtion(write):
    """write to file the result"""
    if write_to_file:
        open(file_name, "a").write(str(write) + "\n")


if proxy:
    proxy = {"http": proxy_ip, "https": proxy_ip}
else:
    proxy = {}

if add_payloads_from_file:
    for payload in open(payloads_file).read().splitlines():
        all_the_xss_payloads.append(payload.strip())

if blind_xss:
    for payload in open("all_the_xss_payloads.txt").read().splitlines():
        if "alert(" in payload:
            all_blind_xss_payloads.append(payload.replace(f'alert({payload.split("alert(")[1].split(")")[0]})',
                                                          f"\"document.location.href = 'http://{my_ip}/';\""))


def finish():
    """
    executed when the script finish or when the script get "keyboard interrupt".
    this function write the final result of the script.
    """
    ################
    "    finish    "
    ################
    print("_" * 108)
    open(file_name, "w").close()

    # print("number of url's:", url_count)
    if massages:
        for massage in massages:
            print(massage)
            write_to_file_funtion(massage)

    print("\nall the statuses\n")
    write_to_file_funtion("\nall the statuses\n")

    did_count = []
    for i in status_count:
        if i not in did_count:
            print(repr(status_count.count(i)) + ":", i)
            did_count.append(i)
            write_to_file_funtion(repr(status_count.count(i)) + ": " + i)

    print()
    for u, var, p, m, w in all_the_things_i_found:
        print(f"url: {u} | method: {m} | where: {w} | parameter {var} | payload: {p}")
        write_to_file_funtion(f"url: {u} | parameter {var} | payload: {p} | method: {m} | where: {w}")

    print("\nfound", len(all_the_things_i_found), 'vulnerability\n')
    write_to_file_funtion("found" + " " + str(len(all_the_things_i_found)) + ' vulnerability\n')

    if take_a_look_at:
        print("error in:")
    write_to_file_funtion("error in:")

    founds = []
    for i in take_a_look_at:
        if i[0] not in founds:
            print(i)
            write_to_file_funtion(i)
            founds.append(i[0])

    for i in all_the_dom_xss_i_found:
        print(i)

    for s, u, var, p, m, w in response_status:
        if str(s)[0] == "5":
            print("status 500\n")
            break

    for s, u, var, p, m, w in response_status:
        if str(s)[0] == "5":
            print(f"status: {str(s)} | url: {u} | method: {m} | where: {w} | parameter {var} | payload: {p}")
            write_to_file_funtion(f"status: {str(s)} | url: {u} | parameter {var} | payload: {p} | method: {m} | where:"
                                  f" {w}")

    print(f"timeouts: {final_timeouts} times")
    exit()


def check_xss(website_url: str, website_method: str, package: str, params="", mime_type_=""):
    """handle with the requests data and start the requester"""
    if mime_type_ == "json":
        json = params
    else:
        json = ""
    if not params:
        params = {}
    else:
        w = ""
        for i in params.split(":"):
            w += reverse_replace(i, ",", "%2C", i.count(",") - 1) + ","
        params = w
        params = ast.literal_eval("{'" + params.replace("=", "\': \'").replace("&", "', '") + "'}")
    p = take_headers_and_cookies = burp_to_python(package.replace("\\n", "\n").replace("\\r", ""))
    if not p:
        return
    try:
        if not take_headers_and_cookies[0].strip():
            cookies = {}
        else:
            cookies = ast.literal_eval(take_headers_and_cookies[0].strip())
            # cookies["NID"] = cookies["NID"] + str(random)
            # print(cookies)
    except (IndexError, TypeError):
        cookies = {}
        if debug:
            print("no cookies")

    headers = ast.literal_eval(str(take_headers_and_cookies[1].split(", ''")[0].strip() + "}").replace("}}", "}"))

    get_parameters = "?" + urlparse(website_url).query
    try:
        for pa in all_the_xss_payloads:
            requester(
                website_method,
                website_url,
                headers,
                cookies,
                params,
                check_alert,
                show_progress,
                requests_timeout,
                get_parameters,
                sleep_time,
                encode(pa, mix=mix),
                proxy=proxy,
                mime_type=mime_type_,
                json_parameters=json,
                check_just_if_he_has_parameters=check_just_if_he_has_parameters,
                check_on_cookies=check_on_cookies
            )
    except IndexError:
        pass
    except KeyboardInterrupt:
        finish()
    ############
    " selenium "
    ############
    # try:
    #     for pa in all_the_xss_payloads:
    #         selenium(
    #             website_method,
    #             website_url,
    #             headers,
    #             cookies,
    #             params,
    #             check_alert,
    #             show_progress,
    #             requests_timeout,
    #             get_parameters,
    #             sleep_time,
    #             encode(pa, mix=mix),
    #             proxy=proxy,
    #             mime_type=mime_type_,
    #             json_parameters=json
    #         )
    # except IndexError:
    #     pass
    # except KeyboardInterrupt:
    #     finish()


def check_connection(website_url):
    """check the connection with the website"""
    try:
        requests.get(website_url)
    except ConnectionError:
        exit("cant connect to " + website_url)


#####################
" script start here "
#####################
if __name__ == '__main__':
    with open(burp_xml_file) as xml_file:
        items = xml_file.read().split("<item>")[1:]
        check_connection(items[0].split("<url><![CDATA[")[1].split("]]")[0])
        url_count = len(items)
        massages = []
        for item_count in range(len(items)):
            item = items[item_count]
            if item.split("<protocol>")[1].split("</protocol>")[0] != "http" and item.split("<protocol>")[1].split("</protocol>")[0] != "https":
                if "non http protocol" not in massages:
                    massages.append("non http protocol")
                    massages.append("maybe we got a websocket")
                continue
            method = item.split("<method><![CDATA[")[1].split("]]></method>")[0]
            url = item.split("<url><![CDATA[")[1].split("]]")[0]
            path = item.split("<path><![CDATA[")[1].split("]]></path>")[0]
            host = item.split("<host")[1].split(">")[1].split("</host>")[0].split("<")[0]
            port = item.split("<port>")[1].split("</port>")[0]
            if port != "80" and port != "443":
                massages.append("different port")
            extension = item.split("<extension>")[1].split("</extension>")[0]
            status_code = item.split("<status>")[1].split("</status>")[0]
            status_count.append(status_code)
            response_length = item.split("<responselength>")[1].split("</responselength>")[0]
            mime_type = item.split("<mimetype>")[1].split("</mimetype>")[0]
            request_packet = repr(b64decode(item.split('<request base64="true"><![CDATA[')[1].split("]]></request>")[0]))[2:-1]
            if request_packet in double:
                continue
            double.append(request_packet)
            if method == "GET":
                any_parameter = "?" in url
            elif method == "POST":
                any_parameter = "\\r\\n\\r\\n" in request_packet
            if any_parameter:
                parameters = request_packet.split("\\r\\n\\r\\n")[1]
                if parameters.count("=") > 1:
                    f = ""
                    for i in parameters.split("="):
                        f += i.replace("&", "%26", i.count("&") - 1) + "="
                    parameters = f[:-1].replace(f[:-1].split("=")[-1], f[:-1].split("=")[-1].replace("&", "%26"))
                else:
                    parameters = parameters.replace("&", "%26")
            if urlparse(url).path.endswith(remove_files_end):
                continue
            if any_parameter:
                for i in "{}[]()":
                    if parameters:
                        if i == parameters[0]:
                            mime_type = "json"
                check_xss(url, method, request_packet, parameters, mime_type_=mime_type)
            else:
                check_xss(url, method, request_packet)

    finish()
