import math

import numpy as np
import pandas as pd
def countCSV(path):
    df = pd.read_csv(path)
    cwe = np.array(df["cwe_id"]).tolist()
    correctly_predicted = np.array(df["correctly_predicted"]).tolist()
    res = {}
    count1 = 0
    count2 = 0
    cwe_id = []
    success = []
    all = []
    rate = []
    for c,p in zip(cwe,correctly_predicted):
        if c in res:
            if p==1:
                res['{}'.format(c)][0]+=1
            res['{}'.format(c)][1] += 1
        else:
            res['{}'.format(c)]=[0,1]
            if p==1:
                res['{}'.format(c)][0]+=1
    for i in res:
        cwe_id.append(i)
        success.append(res[i][0])
        all.append(res[i][1])
        rate.append(res[i][0]/res[i][1])
    df = pd.DataFrame()
    df['cwe_id']=cwe_id
    df['correctly_predicted']=success
    df['all']=all
    df['accuracy']=rate
    # df.to_csv("stat_"+path.split("/")[2])
    df.to_csv("2.csv")
def cwesta(path):
    f = open(path,'r',encoding="utf-8")
    res = {}
    cwe = []
    match = []
    preds = f.read().splitlines()
    for i in range(len(preds)):
        if preds[i] == "source:":
            cwe_tem =preds[i+1].split()[0]
            cwe.append(cwe_tem)
        if preds[i] == "match:":
            match.append(int(preds[i + 1]))
    cwe_id = []
    success = []
    all = []
    rate = []
    for c, p in zip(cwe, match):
        if c in res:
            if p == 1:
                res['{}'.format(c)][0] += 1
            res['{}'.format(c)][1] += 1
        else:
            res['{}'.format(c)] = [0, 1]
            if p == 1:
                res['{}'.format(c)][0] += 1
    for i in res:
        cwe_id.append(i)
        success.append(res[i][0])
        all.append(res[i][1])
        rate.append(res[i][0] / res[i][1])
    df = pd.DataFrame()
    df['cwe_id'] = cwe_id
    df['correctly_predicted'] = success
    df['all'] = all
    df['accuracy'] = rate
    df.to_csv("stat_{}.csv".format(path.split("/")[1]))
def diffallstat(path1):
    f_raw_preds = open(path1,'r',encoding="utf-8")
    f_group = pd.read_csv("diff/cve_fixes_test_diff.csv")
    preds = f_raw_preds.read().splitlines()
    group = np.array(f_group["group"]).tolist()
    preds_acc = []
    for i in range(len(preds)):
        if preds[i]=="match:":
            preds_acc.append(int(preds[i+1]))
    all_group = set(group)
    res_match = []
    for g_to_cal in all_group:
        match =1
        for p,g in zip(preds_acc,group):
            if g==g_to_cal:
                match&=p
        res_match.append(match)
    print(sum(res_match)/len(res_match))
def proallstat(path1):
    f_raw_preds = open(path1,'r',encoding="utf-8")
    f_group = pd.read_csv("prompt/cve_fixes_test_prompt.csv")
    preds = f_raw_preds.read().splitlines()
    group = np.array(f_group["group"]).tolist()
    preds_acc = []
    for i in range(len(preds)):
        if preds[i]=="match:":
            preds_acc.append(int(preds[i+1]))
    all_group = set(group)
    res_match = []
    for g_to_cal in all_group:
        match =1
        for p,g in zip(preds_acc,group):
            if g==g_to_cal:
                match&=p
        res_match.append(match)
    print(sum(res_match)/len(res_match))
def tokenlenstat(path1,tokenizer_name):
    model_name = path1.split("/")[2]
    model_name = model_name.split("_")[0]
    f = open(path1,'r',encoding="utf-8")
    preds = f.read().splitlines()
    from transformers import RobertaTokenizer
    tokenizer = RobertaTokenizer.from_pretrained(tokenizer_name)
    tokenizer.add_tokens(["<S2SV_StartBug>", "<S2SV_EndBug>", "<S2SV_blank>", "<S2SV_ModStart>", "<S2SV_ModEnd>"])
    source = []
    match = []
    tokenlen = []
    for i in range(len(preds)):
        if preds[i]=="match:":
            match.append(int(preds[i+1]))
        if preds[i] == "source:":
            source.append(preds[i+1])
            tokenlen.append(len(tokenizer.encode(preds[i+1])))
    m_all = []
    len_all = []
    idx = []
    for i in range(10):
        idx.append("{}-{}".format(50*i,50*(i+1)))
    idx.append(">500")
    for i in range(11):
        m_all.append(0)
        len_all.append(0)
    for m,t,s in zip(match,tokenlen,source):
        if t>500:
            len_all[10]+=1
            if m ==1:
                m_all[10]+=1
        else:
            to_go = math.floor(t/50)
            len_all[to_go] += 1
            if m == 1:
                m_all[to_go] += 1
    df = pd.DataFrame()
    df["source"] = source
    df["match"] = match
    df["tokenlen"] = tokenlen
    df.to_csv("./Original/{}_stat.csv".format(model_name))
    df2 = pd.DataFrame()
    df2["idx"]=idx
    df2["match"]=m_all
    df2["all"] = len_all
    df2.to_csv("./Original/{}_stat4.csv".format(model_name))
def accu(path):
    f_raw_preds = open(path, 'r', encoding="utf-8")
    preds = f_raw_preds.read().splitlines()
    preds_acc = []
    for i in range(len(preds)):
        if preds[i] == "match:":
            preds_acc.append(int(preds[i + 1]))
    print(sum(preds_acc)/len(preds_acc))
def counttop10all(path):
    cwe_ids = ["CWE-119","CWE-125","CWE-20","CWE-399","CWE-264","CWE-476","CWE-362","CWE-787","CWE-190","CWE-200"]
    df = pd.read_csv(path)
    id = df["cwe_id"]
    cp = df["correctly_predicted"]
    all = df["all"]
    all_cp = 0
    all_all = 0
    for i,c,a in zip(id,cp,all):
        if i in cwe_ids:
            all_cp+=c
            all_all+=a
    print(all_cp/all_all)
def countaccu(path):
    df = pd.read_csv(path)
    c_p = np.array(df["correctly_predicted"]).tolist()
    all = np.array(df["all"]).tolist()
    count1 = sum(c_p)
    count2 = sum(all)
    print(count1/count2)
    print(count2)
def nkproallstat(n):
    f_raw_preds = open("5kprompt/CodeT5_ori_{}.txt".format(n),'r',encoding="utf-8")
    f_group = pd.read_csv("5kprompt/{}/cve_fixes_test.csv".format(n))
    preds = f_raw_preds.read().splitlines()
    group = np.array(f_group["group"]).tolist()
    preds_acc = []
    for i in range(len(preds)):
        if preds[i]=="match:":
            preds_acc.append(int(preds[i+1]))
    all_group = set(group)
    res_match = []
    for g_to_cal in all_group:
        match =1
        for p,g in zip(preds_acc,group):
            if g==g_to_cal:
                match&=p
        res_match.append(match)
    print(sum(res_match)/len(res_match))
def nkdiffallstat(n):
    f_raw_preds = open("5kdiff/UniXcoder/UniXcoder_ori_{}.txt".format(n),'r',encoding="utf-8")
    f_group = pd.read_csv("5kdiff/{}/cve_fixes_test.csv".format(n))
    preds = f_raw_preds.read().splitlines()
    group = np.array(f_group["group"]).tolist()
    preds_acc = []
    for i in range(len(preds)):
        if preds[i]=="match:":
            preds_acc.append(int(preds[i+1]))
    all_group = set(group)
    res_match = []
    for g_to_cal in all_group:
        match =1
        for p,g in zip(preds_acc,group):
            if g==g_to_cal:
                match&=p
        res_match.append(match)
    print(sum(res_match)/len(res_match))
if __name__ =="__main__":
    # accu("UniXcoder_ori_1.txt")
    # accu("UniXcoder_ori_3.txt")
    nkdiffallstat(1)
    nkdiffallstat(2)
    nkdiffallstat(3)
    nkdiffallstat(4)
    # accu("nofinetune/CodeBERT/CodeBERT_0.txt")
    # accu("nofinetune/CodeBERT/CodeBERT_0.2.txt")
    # accu("nofinetune/CodeBERT/CodeBERT_0.4.txt")
    # accu("nofinetune/CodeBERT/CodeBERT_0.6.txt")
    # accu("nofinetune/CodeBERT/CodeBERT_0.8.txt")
    # accu("nofinetune/CodeT5/CodeT5_0.txt")
    # accu("nofinetune/CodeT5/CodeT5_0.2.txt")
    # accu("nofinetune/CodeT5/CodeT5_0.4.txt")
    # accu("nofinetune/CodeT5/CodeT5_0.6.txt")
    # accu("nofinetune/CodeT5/CodeT5_0.8.txt")
    # accu("nofinetune/GraphCodeBERT/GraphCodeBERT_0.txt")
    # accu("nofinetune/GraphCodeBERT/GraphCodeBERT_0.2.txt")
    # accu("nofinetune/GraphCodeBERT/GraphCodeBERT_0.4.txt")
    # accu("nofinetune/GraphCodeBERT/GraphCodeBERT_0.6.txt")
    # accu("nofinetune/GraphCodeBERT/GraphCodeBERT_0.8.txt")
    # accu("nofinetune/UniXcoder/UniXcoder_0.txt")
    # accu("nofinetune/UniXcoder/UniXcoder_0.2.txt")
    # accu("nofinetune/UniXcoder/UniXcoder_0.4.txt")
    # accu("nofinetune/UniXcoder/UniXcoder_0.6.txt")
    # accu("nofinetune/UniXcoder/UniXcoder_0.8.txt")
    # accu("beam/CodeBERT/CodeBERT_400.txt")
    # cwesta("ori/CodeBERT/CodeBERT_ori.txt")
    # cwesta("ori/CodeT5/CodeT5_ori.txt")
    # cwesta("ori/GraphCodeBERT/GraphCodeBERT_ori.txt")
    # cwesta("ori/UniXcoder/UniXcoder_ori.txt")
    # accu("beam/UniXcoder/UniXcoder_200.txt")
    # proallstat("prompt/CodeT5/CodeT5_prompt.txt")
    # proallstat("prompt/CodeBERT/CodeBERT_prompt.txt")
    # proallstat("prompt/GraphCodeBERT/GraphCodeBERT_prompt.txt")
    # proallstat("prompt/UniXcoder/UniXcoder_prompt.txt")
    # diffallstat("diff/CodeT5/CodeT5_diff.txt")
    # diffallstat("diff/CodeBERT/CodeBERT_diff.txt")
    # diffallstat("diff/GraphCodeBERT/GraphCodeBERT_diff.txt")
    # diffallstat("diff/UniXcoder/UniXcoder_diff.txt")
    # accu("abs/GraphCodeBERT_abs.txt")
    # accu("./5Kloop/CodeT5/CodeT5_ori_0.txt")
    # accu("./5Kloop/CodeT5/CodeT5_ori_1.txt")
    # accu("./5Kloop/CodeT5/CodeT5_ori_2.txt")
    # accu("./5Kloop/CodeT5/CodeT5_ori_3.txt")
    # accu("newdata/wordlevel/UniXcoder/UniXcoder_wordlevel.txt")
    # accu("./5Kloop/CodeT5/CodeT5_wordlevel_0.txt")
    # accu("./5Kloop/CodeT5/CodeT5_wordlevel_1.txt")
    # accu("./5Kloop/CodeT5/CodeT5_wordlevel_2.txt")
    # accu("./5Kloop/CodeT5/CodeT5_wordlevel_3.txt")
    # accu("./5Kloop/CodeT5/CodeT5_wordlevel_4.txt")
    # counttop10all("statistic/stat_CodeBERT_raw_preds.csv")
    # counttop10all("statistic/stat_CodeT5_raw_preds.csv")
    # counttop10all("statistic/stat_GraphCodeBERT_raw_preds.csv")
    # counttop10all("statistic/stat_UniXcoder_raw_preds.csv")
    # countCSV("./word-level/CodeBERT (Word-level Tokenizer)_raw_preds.csv")
    # countCSV("./word-level/GraphCodeBERT (Word-level Tokenizer)_raw_preds.csv")
    # countCSV("./word-level/CodeT5 (Word-level Tokenizer)_raw_preds.csv")
    # countCSV("./word-level/UniXcoder (Word-level Tokenizer)_raw_preds.csv")
    # countCSV("./Original/CodeBERT_raw_preds.csv")
    # countCSV("./Original/GraphCodeBERT_raw_preds.csv")
    # countCSV("./Original/CodeT5_raw_preds.csv")
    # countCSV("./Original/UniXcoder_raw_preds.csv")
    # countCSV("./No_ctx/CodeBERT_no_ctx_raw_preds.csv")
    # countCSV("./No_ctx/GraphCodeBERT_no_ctx_raw_preds.csv")
    # countCSV("./No_ctx/CodeT5_no_ctx_raw_preds.csv")
    # countCSV("./No_ctx/UniXcoder_no_ctx_raw_preds.csv")
    # diffabsstat(50, "circle/CodeBERT_abs3.txt")
    # diffabsstat(50, "circle/CodeT5_abs.txt")
    # diffabsstat(50, "circle/GraphCodeBERT_abs3.txt")
    # diffabsstat(50, "circle/UniXcoder_abs3.txt")
    # accu("beam_size/beam_size 300/CodeBERT_300.txt")
    # tokenlenstat("./Original/CodeBERT_ori.txt","microsoft/codebert-base")
    # tokenlenstat("./Original/CodeT5_ori.txt", "Salesforce/codet5-base")
    # tokenlenstat("./Original/GraphCodeBERT_ori.txt", "microsoft/graphcodebert-base")
    # tokenlenstat("./Original/UniXcoder_ori.txt", "microsoft/unixcoder-base")
    # accu("beam_size/beam_size 300/UniXcoder_300.txt")
    # accu("beam_size/beam_size 400/CodeBERT_400.txt")
    # accu("beam_size/beam_size 400/GraphCodeBERT_400.txt")
    # accu("beam_size/beam_size 400/UniXcoder_400.txt")
    # countCSV("test.csv")
