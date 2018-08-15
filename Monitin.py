import os
import hashlib
from datetime import *
import requests


def FileToHash(path):
    f = open(path, 'rb')
    h = hashlib.md5()
    h.update(f.read())
    ha = h.hexdigest()
    return ha


def CalculateFile():
    path = raw_input('enter file path: ')
    #print FileToHash(path)
    return FileToHash(path)


def CalculateFolder():
    mypath = raw_input('enter folder path: ')
    lst_files = os.listdir(mypath)
    Results = {}

    for file in lst_files:
        file_path = mypath + '\\' + file
        if os.path.isfile(file_path):
            #readfile = open(file_path, 'rb')
            md5 = FileToHash(file_path)
            rate = GetReport(md5)

            Results[file] = {'MD5': md5, 'SIZE (KB)': GetSize(file_path), 'CHANGETIME': ChangeTime(file_path), 'EXECUTABLE': IsExecutable(file_path), 'RATE': rate}

    #below is the syntax to return my dictionary in a neat readable table
    print "{:<50} {:<50} {:<50} {:<50} {:<50}".format('MD5', 'SIZE (KB)', 'CHANGETIME', 'EXECUTABLE', 'RATE')
    for k, v in Results.iteritems():
        print "{:<50} {:<50} {:<50} {:<50} {:<50}".format(v['MD5'], v['SIZE (KB)'], v['CHANGETIME'], v['EXECUTABLE'], v['RATE'])


def IsExecutable(file_path):

    readfile = open(file_path, 'rb')
    if readfile.read()[:2] == 'MZ':
        executable = True
    else:
        executable = False

    return executable

#def DictionaryToTable (ResultsDict):


'''def CalculateRate(positives, total, isexec):

    pos
    if data['verbose_msg'] == 'The requested resource is not among the finished, queued or pending scans':
        rate = 0.9
    else:
        if executable

        rate = data['positives'] / data['total']
        if not executable then divide by 2

    return rate'''



def GetSize(file_path):
    complicated_size = os.path.getsize(file_path)
    size = float(complicated_size) / 1024
    return size


def ChangeTime(file_path):
    changetime = os.path.getctime(file_path)
    readabletime = datetime.fromtimestamp(changetime).strftime('%c')
    return readabletime

def GetReport(md5):

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    apikey = '9251624a0029374f3fecf9f1b28b3940a3184704a64dbe66771bb40503778c37'
    params = {'apikey': apikey, 'resource': md5}
    response = requests.get(url, params = params)
    data = response.json()

    if data['verbose_msg'] == 'The requested resource is not among the finished, queued or pending scans':
        rate = 0.9
    else:
        # this should be - if executable then rate is as below
        rate = data['positives'] / data['total']
        # add in here - else: and then if the file is not executable then divide the rate by 2

    return rate


def main():
    print '- - Welcome to the super cool Monitin Programme - - '

    print 'Please select action:'

    option = input('[1] Enter File Path to Receive Hash\n' \
                '[2] Enter Folder Path to Receive Hashes of all Files Within\n'\
                '>\t')

    if option == 1:
        CalculateFile()
    else:
        CalculateFolder()



if __name__ == '__main__':
    main()

#my program works!!
# to make it better, separate theings into separate functions to make it neater. also fix up the date so that it's day, month, year.
# also fix up the rate thing - to add the executable or not rate - see notes above, and put the if executable or not into its own function.
#add the sysv argument line at the bottom so that this program can run from cmd with an argument.
# also add that when searching if a file is executable or not, add that it should check if either the binary begins MZ or the last 4
# characters are .exe - coz both could be exe so it's better. and maybe display which one it is.

