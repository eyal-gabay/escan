import requests


class Main:
    """burp to python"""
    def __init__(self):
        self.http = "http"
        self.appender = []
        self.cookies = ""
        self.data = ""

    def __repr__(self):
        return "burp to python"

    def print_request(self):
        return
        # print(f"""
# import requests
#
# r = requests.{self.order[0].split()[0].lower()}(\"{self.url}\", headers={self.json}, {self.cookies}, {self.proxie})
#
# """)

    def get(self):
        self.print_request()

    def post(self):
        self.print_request()

    def __call__(self, request: str, burp_proxie=False):
        if burp_proxie:
            self.proxie = 'proxies={"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}'
        else:
            self.proxie = ""
        b = ""
        for l in request.strip().splitlines():
            if l.startswith("Cookie:"):
                self.cookies_data = ""
                # rw = ""
                # for i in range(len(l.strip("Cookie:").strip())):
                #     if l.strip("Cookie:").strip()[i - 1] != ";" or l.strip("Cookie:").strip()[i] != " ":
                #         rw += l.strip("Cookie:").strip()[i]
                # print(rw)
                rw = l.strip("Cookie:").strip().replace(" ", "").replace(";", "; ")
                for i in rw.split(";"):
                    if i.count("=") > 1:
                        self.cookies_data += i.replace(" ", "', '").replace("=", "': '", i.count("=") - (i.count("=") - 1))
                    else:
                        self.cookies_data += i.replace(" ", "', '").replace("=", "': '")
                for i in range(len(l)):
                    if l[i] == "=":
                        try:
                            if l[i + 1] == "=" or l[i + 1] == ";":
                                b += l[i]
                        except IndexError:
                            pass
                        else:
                            b += '\': \''
                    else:
                        b += l[i]
                f = ""
                self.cookies = "{'" + self.cookies_data + "'}"

        self.s = request.strip().splitlines()
        self.s.remove(self.s[0])
        for i in self.s:
            if not i.startswith("Cookie"):
                self.appender.append(f'\'{i}\''.replace(": ", "\': \'"))
        else:
            self.string = ", ".join(self.appender)
        self.json = "{" + self.string + "}"
        self.order = request.strip().splitlines()
        # self.url = self.http + "://" + self.order[1].split()[1] + self.order[0].split()[1]
        if self.order[0].split()[0] == "GET":
            self.get()
            return [self.cookies, self.json]
        elif self.order[0].split()[0] == "POST":
            self.post()
            # print(self.cookies)
            return [self.cookies, self.json]


burp_to_python = Main()

if __name__ == '__main__':
    pass
    print(burp_to_python("""
POST /api/mortgage/preapproval-page-actions HTTP/2
Host: better.com
Cookie: _hp2_id.1497711400=%7B%22userId%22%3A%226226552788736822%22%2C%22pageviewId%22%3A%222753463526836712%22%2C%22sessionId%22%3A%224877246893645771%22%2C%22identity%22%3A%221768324%22%2C%22trackerVersion%22%3A%224.0%22%2C%22identityField%22%3Anull%2C%22isIdentified%22%3A1%2C%22oldIdentity%22%3Anull%7D; _gcl_au=1.1.2116349513.1616859443; _lc2_fpi=1d5e8c2a202d--01f1t5abrwmwgn46dnc6j7jt0v; _ga=GA1.2.793190928.1616859444; _fbp=fb.1.1616859447315.1594218462; fs_uid=rs.fullstory.com#1GkE#5798860730933248:6615695001657344#4bd6283a#/1648892238; ki_t=1616859450060%3B1617030967277%3B1617038015429%3B3%3B24; ki_r=; __pdst=abb5fc581d714afe86dcfd93cd259957; ajs_user_id=1768324; ki_s=; _gid=GA1.2.1497293976.1617132384; better-session=%7B%22authenticated%22%3A%7B%22authenticator%22%3A%22authenticator%3Acustom%22%2C%22sessionId%22%3A%22Opwii%2Bg6WPAdbVm4At0RFgYlvQ6NSJjv9s9o3%2FRN15KxzBmucaSN2FdG5yMZTqw%2FFXtru2e7Y0NQOontt5yTLGJfUr9kZtj%2FT74Hx6kFA6SxNvPHEIiDZ568JvsVm7hY4NRcFsU1Ti25tM61fGD%2FLl3sL9TsKZ2CGifsi%2FJFwlm9lA7nTpqLS%2FJRteoXjMf%2BNUqEct3T7hYBxP8y30uy63iLtnIu0kBEqzKqh3nKpkYhJ495VzOi%2Fpwu91B80aXkG3P%2BtiFbpdBlw5lwY4a2%2FDLq%2FyGDmj0p8P1MJbUd1fnfYLeZ5HBp6nd%2B%2BV807GrbLWjU7yPwcdNS82HI5j81IFKvfG1NA%2FkX5y2t%2BLaFoU2Oi4CVWRVW4Rh6AgSQkHQy5QZZs2NbxfqnMoP8IJfNGp7K3A%2BW5QG8BafXh0BSvX%2FwMx%2BRzPSxkEjTpR5p1vNWlclO6MJ5B5GQ2N0dyBb5y05Qr%2FuDMqjbZ4sSQEH9Dlym5Sly1LwPvrBizHI7bNfn%22%2C%22creationTimestamp%22%3A1617455124008%2C%22expiresMs%22%3A86400000%2C%22expiresTimestamp%22%3A1617541524008%2C%22isAdmin%22%3Afalse%2C%22email%22%3A%22erik%40better.com%22%2C%22userId%22%3A1768324%2C%22accountUuid%22%3A%2227ba468c-93be-47e6-8e45-4fe002224ef9%22%7D%7D; better-session-expiration_time=86400; G_ENABLED_IDPS=google; ajs_anonymous_id=%22ee32eb24-8839-4b28-a700-85338fd44a77%22; ds_brand_rollout=5a21cb93-7327-4121-a223-03a6a6427d52; _li_dcdm_c=.better.com; fcaid=f836d0b78145ef85fd8f8935b13bf5491c728bc07ca54a08b0720b9f2342f5f1; fcuid=9c7699b9-e561-4218-9a7a-b206e86578de; fccid=d074ff89-c5a0-4615-8b9d-1485e11b028f; _dd_s=rum=0&expire=1617456086730; _hp2_ses_props.1497711400=%7B%22ts%22%3A1617455105858%2C%22d%22%3A%22better.com%22%2C%22h%22%3A%22%2Fsign-in%22%2C%22q%22%3A%22%3FtimedOut%3Dtrue%22%7D; resume-preapp=%7B%22preapprovalUuid%22%3A%22d60092fc-33bf-447d-b6d5-a25000063e1a%22%2C%22hasAccount%22%3Atrue%2C%22isRefinance%22%3Afalse%7D; _uetsid=cfb51d50918d11eb80424f5681a15d4e; _uetvid=529c0ad08f1211eb9b6367e5f3668e60
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://better.com/preapproval/d60092fc-33bf-447d-b6d5-a25000063e1a/credit-info
Content-Type: application/json
Origin: https://better.com
Content-Length: 144
Te: trailers
Connection: close

{"preapprovalPageAction": {"preapprovalUuid": "28e1931c-9e29-4110-8d6d-56b3bf9159b8", "initiatingPageName": "previous", "actionName": "jump"}}""", False))
