import array
from PIL import Image
import os
import r2pipe, re, json
import numpy as np
from collections import Counter
from sklearn.feature_extraction import FeatureHasher


def hashing(input,size,input_type="string"):
    return FeatureHasher(size, input_type=input_type).transform([input]).toarray()[0]

def convert_bin_to_raw_image(pathRead,width):
    try:
        f = open(pathRead,'rb');
        ln = os.path.getsize(pathRead);
        rem = ln%width;
        a = array.array("B");
        a.fromfile(f,ln-rem);
        f.close();
        g = np.reshape(a,(int(len(a)/width),width));
        g = np.uint8(g);
        g = Image.fromarray(g.astype('uint8'))
        g = g.resize((width,width));
        return g
    except:
        print("Error")

def convert_bin_to_image(pathRead,width):
    try:
        f = open(pathRead,'rb');
        ln = os.path.getsize(pathRead);
        rem = ln%width;
        a = array.array("B");
        a.fromfile(f,ln-rem);
        f.close();
        g = np.reshape(a,(int(len(a)/width),width));
        g = np.uint8(g);
        g = Image.fromarray(g.astype('uint8'))
        g = g.resize((width,width));
        g = np.array(g)
        return g
        # f = open(pathSave,"wb")
        # pickle.dump(g,f)
        # f.close()
    except:
        print("Error")

def convert_bin_to_image_height(pathRead,width,height):
    try:
        f = open(pathRead,'rb');
        ln = os.path.getsize(pathRead);
        rem = ln%width;
        a = array.array("B");
        a.fromfile(f,ln-rem);
        f.close();
        g = np.reshape(a,(int(len(a)/width),width));
        g = np.uint8(g);
        g = Image.fromarray(g.astype('uint8'))
        g = g.resize((width,height));
        g = np.array(g)
        return g
    except:
        print("Error")

def convert_bin_to_HexDump(pathRead):
    try:
        fh = open(pathRead, 'rb')
        hexdump = list(fh.read())
        dic = Counter(hexdump)
        arr = []
        for i in range(256):
            arr.append(dic[i])
        arr = np.asarray(arr)
        return arr

    except:
        print("Error")


def convert_bin_to_HexDump2bytes(pathRead):
    try:
        fh = open(pathRead, 'rb')
        hexdump = list(fh.read())
        twoBytesHexDump = []
        for i in np.arange(0,len(hexdump)-1,2):
            twoBytesHexDump.append((hexdump[i] << 8)+hexdump[i+1])

        dic = Counter(twoBytesHexDump)
        arr = []
        for i in range(2 << 15):
            try:
                arr.append(dic[i])
            except:
                arr.append(0)
        arr = np.asarray(arr)
        return arr

    except:
        print("Error")

def convert_bin_to_HexDump2bytes_hashed(pathRead,size=1024):
    # try:
        fh = open(pathRead, 'rb')
        hexdump = list(fh.read())
        twoBytesHexDump = {}
        for i in np.arange(0,len(hexdump)-1,2):
            k = str((hexdump[i] << 8)+hexdump[i+1])
            try:
                twoBytesHexDump[k] =  twoBytesHexDump[k] + 1
            except:
                twoBytesHexDump[k] = 1

        return FeatureHasher(size, input_type="dict").transform([twoBytesHexDump]).toarray()[0]


def convert_bin_to_HexDumpNbytes_hashed(pathRead,N=3,size=1024):
    # try:
        fh = open(pathRead, 'rb')
        hexdump = list(fh.read())
        NBytesHexDump = {}
        for i in np.arange(0,len(hexdump)-(N-1),N):
            k = 0
            for j in range(N):
                k += hexdump[i+j] << (8*(N-1-j))
            k = str(k)
            try:
                NBytesHexDump[k] =  NBytesHexDump[k] + 1
            except:
                NBytesHexDump[k] = 1
        return FeatureHasher(size, input_type="dict").transform([NBytesHexDump]).toarray()[0]




def convert_bin_to_String_Rep(pathRead):
    # try:
    r2 = r2pipe.open(pathRead, flags=['-2'])
    r2.cmd("aaa")


    fs = "strings"
    fs_Meta, fistByteAddress = {}, ""
    fsJsons = r2.cmdj("fsj")
    for fj in fsJsons:
        if fj["name"]  ==  fs:
            fs_Meta[fj["name"]] = fj["count"]

    try:
        if not fs_Meta[fs] > 0:
            return None
    except KeyError:
        return None

    st = r2.cmdj("fs " + fs + "; fj")

    fs_count_size = {}
    for fsDet in st:
        fsName = fsDet["name"]
        try:
            if "init" in fsName:
                fistByteAddress = fsDet["paddr"]
        except:
            return None

        captureFlag = 0
        pattern = re.compile(r'[a-zA-Z0-9]{1,}', re.I)
        for xtm in pattern.findall(fsName):
            if len(xtm) > 3:
                captureFlag = 1
                break
        if captureFlag == 1:
            if fsName not in fs_count_size:
                fs_count_size[fsName] = []
                fs_count_size[fsName].append(1)
                fs_count_size[fsName].append(int(fsDet["size"]))
            else:
                fs_count_size[fsName][0] += 1
                fs_count_size[fsName][1] += int(fsDet["size"])
            captureFlag = 0

    del st
    return set(fs_count_size.keys())


def convert_bin_to_Relocs_Rep(pathRead):
    # try:
    r2 = r2pipe.open(pathRead, flags=['-2'])
    r2.cmd("aaa")


    fs = "relocs"
    fs_Meta, fistByteAddress = {}, ""
    fsJsons = r2.cmdj("fsj")
    for fj in fsJsons:
        if fj["name"]  ==  fs:
            fs_Meta[fj["name"]] = fj["count"]

    try:
        if not fs_Meta[fs] > 0:
            return None
    except KeyError:
        return None

    st = r2.cmdj("fs " + fs + "; fj")

    fs_count_size = {}
    for fsDet in st:
        fsName = fsDet["name"]
        try:
            if "init" in fsName:
                fistByteAddress = fsDet["paddr"]
        except:
            return None

        if fsName not in fs_count_size:
            fs_count_size[fsName] = []
            fs_count_size[fsName].append(1)
            fs_count_size[fsName].append(int(fsDet["size"]))
        else:
            fs_count_size[fsName][0] += 1
            fs_count_size[fsName][1] += int(fsDet["size"])

    del st
    return set(fs_count_size.keys())



def convert_bin_to_Sections_Rep(pathRead):
    # try:
    r2 = r2pipe.open(pathRead, flags=['-2'])
    r2.cmd("aaa")


    fs = "sections"
    fs_Meta, fistByteAddress = {}, ""
    fsJsons = r2.cmdj("fsj")
    for fj in fsJsons:
        if fj["name"]  ==  fs:
            fs_Meta[fj["name"]] = fj["count"]

    try:
        if not fs_Meta[fs] > 0:
            return None
    except KeyError:
        return None

    st = r2.cmdj("fs " + fs + "; fj")

    fs_count_size = {}
    for fsDet in st:
        fsName = fsDet["name"]
        try:
            if "init" in fsName:
                fistByteAddress = fsDet["paddr"]
        except:
            return None

        if fsName not in fs_count_size:
            fs_count_size[fsName] = []
            fs_count_size[fsName].append(1)
            fs_count_size[fsName].append(int(fsDet["size"]))
        else:
            fs_count_size[fsName][0] += 1
            fs_count_size[fsName][1] += int(fsDet["size"])

    del st
    return set(fs_count_size.keys())

def convert_bin_to_Functions_Rep(pathRead):
    # try:
    r2 = r2pipe.open(pathRead, flags=['-2'])
    r2.cmd("aaa")


    fs = "functions"
    fs_Meta, fistByteAddress = {}, ""
    fsJsons = r2.cmdj("fsj")
    for fj in fsJsons:
        if fj["name"]  ==  fs:
            fs_Meta[fj["name"]] = fj["count"]

    try:
        if not fs_Meta[fs] > 0:
            return None
    except KeyError:
        return None

    st = r2.cmdj("fs " + fs + "; fj")

    fs_count_size = {}
    for fsDet in st:
        fsName = fsDet["name"]

        if fsName not in fs_count_size:
            fs_count_size[fsName] = []
            fs_count_size[fsName].append(1)
            fs_count_size[fsName].append(int(fsDet["size"]))
        else:
            fs_count_size[fsName][0] += 1
            fs_count_size[fsName][1] += int(fsDet["size"])

    del st
    return set(fs_count_size.keys())


def convert_bin_to_Imports_Rep(pathRead):
    r2 = r2pipe.open(pathRead, flags=['-2'])
    r2.cmd("aaa")
    # st = r2.cmdj("fs imports; fj")
    st = r2.cmd("fs imports; fj")

    while True:
        ind = st.find("\\x")
        if ind == -1:
            break
        st = st[:ind] + st[ind+4:]
    while True:
        ind = st.find("\\u")
        if ind == -1:
            break
        st = st[:ind] + st[ind+6:]

    st = json.loads(st)
    list_imports = []
    if st!=  None:
        for x in range(len(st)):
            n = re.sub(r'[^a-zA-Z0-9]', '', st[x]['realname'])
            list_imports.append(n)

        return list_imports
    else:
        return None
