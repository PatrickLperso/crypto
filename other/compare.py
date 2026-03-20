import requests
from bs4 import BeautifulSoup
import pandas as pd

def clean_data(x):
    data = x.select('td')

    challenge_date = data[0].text
    challenge_name = data[1].text
    challenge_category = data[2].text
    challenge_point = int(data[3].select('span')[0].text.strip(" "))
    return challenge_date, challenge_name, challenge_category, challenge_point

def index(clean_data):
    keys = [a+"_"+b for a,b in zip(list(map(lambda x:x[1], clean_data)), list(map(lambda x:x[2], clean_data)))]
    return keys

def get_data(username):
    url = f"https://cryptohack.org/user/{username}/"

    # 1️⃣ Faire la requête HTTP
    response = requests.get(url)
    response.raise_for_status()  # Vérifie qu'il n'y a pas d'erreur


    soup = BeautifulSoup(response.text, "html.parser")

    # take the lastest recentUserSolves because of solutions possibly published
    challenges = soup.select('div[class="recentUserSolves"]')[-1].select(' table > tbody > tr')

    challenges_clean = list(map(lambda x:clean_data(x),challenges))

    columns = ["date","category", "name", "points"]
    return pd.DataFrame(challenges_clean, index = index(challenges_clean), columns=columns)

def intersection(data_myself, data_other):

    only_myself = data_myself.loc[~data_myself.index.isin(data_other.index)]
    only_other  = data_other.loc[~data_other.index.isin(data_myself.index)]
    common      = data_myself.loc[data_myself.index.isin(data_other.index)]

    return only_myself, only_other, common

if __name__ == "__main__":

    username_myself = "patrickl_sc"
    username_other = "kiseia"

    data_myself = get_data(username_myself)
    data_other = get_data(username_other)

    compare = intersection(data_myself, data_other)

    only_myself = compare[0]
    only_in_other = compare[1]
    common = compare[2]

    group_by_myself = only_myself.groupby("category").sum("points")
    group_by_other = only_in_other.groupby("category").sum("points")
    group_by_difference = group_by_myself.sub(group_by_other, fill_value=0)

    score_difference = group_by_difference.sum().iloc[0]
    print(f' \n ============= Difference:{score_difference} =========')
    print(group_by_difference)


    group_by_common = common.groupby("category").sum("points")

    score_common = group_by_common.sum().iloc[0]
    print(f'\n  ========= common :{score_common} ========= ')
    print(group_by_common)




