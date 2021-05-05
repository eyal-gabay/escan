# -*- coding: utf-8 -*-


def json(json_request: str, payload: str):
    jsons_with_payloads = []
    strings = json_request.split("\"")
    for i in range(len(strings)):
        if i % 2:
            jsons_with_payloads.append((json_request.replace(strings[i], payload), strings[i]))
    return jsons_with_payloads


def reverse_replace(text: str, str1: str, str2: str, count=0):
    return text[::-1].replace(str1[::-1], str2[::-1], count)[::-1]

