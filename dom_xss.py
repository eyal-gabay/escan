es = "e" * 20
all_the_dom_xss_i_found = []
add = all_the_dom_xss_i_found.append


def dom_xss(html: str, payload, url):
    """
    really basic static dom xss finder.
    find the payload in risky functions or attributes
    """
    if "<!doctype html>" in html or "<!DOCTYPE html>" in html:
        methods = ["write", "writeln", "add", "after", "append", "animate", "insertAfter", "insertBefore",
                   "before", "html", "prepend", "replaceAll", "replaceWith", "wrap", "wrapInner", "wrapAll", "has",
                   "constructor", "init", "index", "jQuery.parseHTML", "$.parseHTML"]
        methods2 = ["innerHTML", "outerHTML", "insertAdjacentHTML", "onevent"]
        try:
            if es in html.split('eval(')[1].split(")")[0]:
                add(f"looks like {url} got eval dom xss")
        except IndexError:
            pass
        for i in methods:
            try:
                if es in html.split(f"{i}(")[1].split(")")[0]:
                    add(f"looks like {url} got {i} dom xss")
            except IndexError:
                pass
        for i in methods2:
            try:
                c = 0
                for i1 in html.split("." + i)[1:]:
                    c += 1
                    if i1[0] == " " or i1[0] == "=":
                        if es in i1.split("=")[1].split('"')[1].split('"')[0] or es in i1.split("=")[1].split("'")[1].split("'")[0]:
                            add(f"looks like {url} got dom xss in the {c} \"{i}\"")
                        else:
                            print(i1)
            except IndexError:
                pass
        if es not in html:
            return "maybe blind xss"
    else:
        pass
        # print(html)
        # raise UserWarning("non html")
