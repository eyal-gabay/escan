count = 0
a = []


def prin(v):
    global a
    if v not in a:
        a.append(v)


with open("xml_files/better.com.xml") as xml_file:
    for item in xml_file.read().split("<item>")[1:]:
        # print(item)
        url = item.split("<url><![CDATA[")[1].split("]]></url>")[0]
        method = item.split("<method><![CDATA[")[1].split("]]></method>")[0]
        if method == "POST":
            prin(url)
            count += 1
        elif method == "GET":
            if "?" in url:
                prin(url)
                count += 1
        else:
            prin(url)
            count += 1
        # break

[print(i) for i in a]
print(len(a))
