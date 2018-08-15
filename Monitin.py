import os
import hashlib
from datetime import *
import requests


def FileToHash(path):
    #receives file path and returns its md5 hash
    f = open(path, 'rb')
    h = hashlib.md5()
    h.update(f.read())
    ha = h.hexdigest()
    return ha


def CalculateFile():
    path = raw_input('enter file path: ')
    return FileToHash(path)


def CalculateFolder():
    #creates a dictionary of file hash, file size, last changed time, if executable or not and the score
    mypath = raw_input('enter folder path: ')
    lst_files = os.listdir(mypath)
    Results = {}

    for file in lst_files:
        file_path = mypath + '\\' + file
        if os.path.isfile(file_path):
            md5 = FileToHash(file_path)
            rate = GetReport(md5)

            Results[file] = {'MD5': md5, 'SIZE (KB)': GetSize(file_path), 'CHANGETIME': ChangeTime(file_path), 'EXECUTABLE': IsExecutable(file_path), 'RATE': rate}

    #below is the syntax to return dictionary in a neat readable table
    print "{:<50} {:<50} {:<50} {:<50} {:<50}".format('MD5', 'SIZE (KB)', 'CHANGETIME', 'EXECUTABLE', 'RATE')
    for k, v in Results.iteritems():
        print "{:<50} {:<50} {:<50} {:<50} {:<50}".format(v['MD5'], v['SIZE (KB)'], v['CHANGETIME'], v['EXECUTABLE'], v['RATE'])


def IsExecutable(file_path):
    #determines if file is executable or not
    readfile = open(file_path, 'rb')
    if readfile.read()[:2] == 'MZ':
        executable = True
    else:
        executable = False
    return executable


def GetSize(file_path):
    #returns size of file
    complicated_size = os.path.getsize(file_path)
    size = float(complicated_size) / 1024
    return size


def ChangeTime(file_path):
    #calculates datetime from last file change
    changetime = os.path.getctime(file_path)
    readabletime = datetime.fromtimestamp(changetime).strftime('%c')
    return readabletime

def GetReport(md5):
    #sends md5 hash to virustotal and calculates its score for a known file. If file is unknown, returns message. 
    #the score of the file determines how suspicious it is based on how many of the anti-viruses classified it as suspicious (positives)
    #divided by the total number of responses from VirusTotal. If file is executable its considered more suspicious, so score is higher.
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    apikey = '9251624a0029374f3fecf9f1b28b3940a3184704a64dbe66771bb40503778c37'
    params = {'apikey': apikey, 'resource': md5}
    response = requests.get(url, params = params)
    data = response.json()

    if data['verbose_msg'] == 'The requested resource is not among the finished, queued or pending scans':
        rate = 0.9
    if not IsExecutable:
        rate = rate/2
    else:
        rate = data['positives'] / data['total']
    return rate


def main():
    print '- - Welcome to the Monitin Programme - -'

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

