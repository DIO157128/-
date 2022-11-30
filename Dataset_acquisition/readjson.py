import json

import pandas as pd


def readjson(path):
    with open(path, 'r', encoding='utf8') as fp:
        json_data = json.load(fp)
        df = pd.DataFrame()
        df1 = pd.DataFrame()
        df2 = pd.DataFrame()
        idx =0
        source_all = []
        language_all = []
        target_all = []
        group_all = []
        for data in json_data:
            code_diffs = data["code_diffs"]
            if len(code_diffs)==0:
                continue
            for diff in code_diffs:
                if diff["code1"]!="" and diff["code2"]!="":
                    group_all.append(idx)
                    source_all.append(diff["code1"])
                    target_all.append(diff["code2"])
                    language_all.append(diff["language"])
            idx+=1
        df["source"]=source_all
        df["target"]=target_all
        df["language"]=language_all
        df["group"]=group_all
        df.to_csv("dl_whole.csv")
        source_py = []
        target_py = []
        group_py = []
        source_cpp = []
        target_cpp = []
        group_cpp = []
        for s,t,l,g in zip(source_all,target_all,language_all,group_all):
            if s !="" and t !="":
                if l ==".py":
                    source_py.append(s)
                    target_py.append(t)
                    group_py.append(g)
                if l ==".cpp":
                    source_cpp.append(s)
                    target_cpp.append(t)
                    group_cpp.append(g)
        df1["source"]=source_py
        df1["target"]=target_py
        df1["group"]=group_py
        df1.to_csv("dl_py.csv")
        df2["source"]=source_cpp
        df2["target"]=target_cpp
        df2["group"]=group_cpp
        df2.to_csv("dl_cpp.csv")


if __name__ == "__main__":
    readjson("commit.json")