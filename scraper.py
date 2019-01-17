import requests
from requests import Request, Session
import re
import os
from bs4 import BeautifulSoup
from delegate import parallelize
import hashlib
import shutil

class MsVNextScraper:

    baseurl = 'http://ms-vnext.net/'
    archiveUrl = baseurl + 'UpdateArchive/'
    supportUrl = 'https://support.microsoft.com/app/content/api/content/help/en-us/'
    nodes = []

    def __init__(self,param):
        self.param = param
        self.download_dir = './downloads'
        self.trust_downloads = self.download_dir + '/trusted'
        self.untrusted_downloads = self.download_dir + '/untrusted'
        self.ensure_dirs()


    def find_matches(self):
        page = requests.get(self.archiveUrl)
        soup = BeautifulSoup(page.text, 'html.parser')
        rows = soup.find_all('tr')

        # init the matches
        matches = []
        #check if the query param is a kb number or a filename
        matches_by_kb = soup.find_all(text=re.compile('[\\d]*'+self.param))
        if len(matches_by_kb) > 0:
            matches = matches_by_kb
        else :
            matches = soup.find_all(text=re.compile('^'+self.param))
        
        for tag in matches:
                parent = tag.find_parent('tr')
                if parent != None:

                    title = parent.find('td',class_='title').text
                    date = parent.find('td',class_='date').text
                    kb = parent.select_one('td[class="kb"]>a').text
                    url = parent.select_one('td[class="files"]>a').get('href')
                    absolute_url = self.baseurl + url            
                    file_name = parent.select_one('td[class="files"] span[class="a"]').text
                    self.nodes.append(Node(title,date, file_name, absolute_url, kb))
                else:
                    print 'no parent found for the match'

        # adds only unique items to the nodes list
        existing = set()
        unique = []
        for obj in self.nodes:
            if obj.file_name not in existing:
                unique.append(obj)
                existing.add(obj.file_name)
        self.nodes = unique

    def ensure_dirs(self):
        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir)
        if not os.path.exists(self.trust_downloads):
            os.makedirs(self.trust_downloads)
        if not os.path.exists(self.untrusted_downloads):
            os.makedirs(self.untrusted_downloads)

    def download_node(self, node):

        trusted = self.trust_confidence(node.kb, node.file_hash_from_url())

        if not trusted:
            print 'Trust confidence is LOW for %s. Potentially malicious file found. Downloading to untrusted' % node.file_name
        else:
            print 'Trust confidence is HIGH for %s' % node.file_name

        local_path = os.path.join(self.untrusted_downloads, node.file_name)
        if os.path.exists(local_path):
            print 'File %s already exists, skipping' % node.file_name
            return False
       
        response = requests.get(node.url, stream = True)
        if response.status_code != 200:
            print 'got status %d for %s' % (response.status_code, node.url)
            response.close()
        print 'Starting to download %s' % node.file_name
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size = 1024):
                if chunk:
                    f.write(chunk)
        print 'Finished downloading %s' % node.file_name
        response.close()
    
    def download_matches(self):
        node_len = len(self.nodes)
        if node_len > 0:
            parallelize(self.download_node, self.nodes)
    
    def verify_downloaded_files(self):
        hash_list = self.create_hashlist_from_path(self.untrusted_downloads)

        # loop through the newer nodes and mark the files as trusted/untrusted
        for node in self.nodes:
            file_name = node.file_name
            file_objs = filter(lambda x: x[1] == file_name, hash_list)
            if len(file_objs) == 1:
                print '\n'
                _file = file_objs[0]
                trusted = self.trust_confidence(node.kb, _file[1])
                if trusted:
                    shutil.move(os.path.join(self.untrusted_downloads, _file[1]), os.path.join(self.trust_downloads, _file[1]))
                    print 'File %s for KB%s can be trusted' % (_file[1], node.kb)
                    print 'Moved the %s file to %s folder' % (_file[1], self.trust_downloads)
                else:
                    print '%s is potentially malicious. It can be found in the %s folder for further analysis' % (_file[1], self.untrusted_downloads)

    
    def trust_confidence(self, kb, file_hash):
        url = self.supportUrl + kb
        response = requests.get(url)
        if re.search(file_hash, response.text, re.IGNORECASE):
            return True
        return False
    
    def sha1(self,fname):
        hash_sha1 = hashlib.sha1()
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha1.update(chunk)
        return hash_sha1.hexdigest()

    def create_hashlist_from_path(self,path):
        hashlist = []
        for root, dirs, files in os.walk(path):
            files.sort()
            for name in files:
                path_to_be_written = root
                path_to_be_written = path_to_be_written.replace(path, "")
                # removing the '/' at the beginning else os.path.join treats it as an absolute path
                # which is not what we want
                if path_to_be_written.startswith('\\'):
                    path_to_be_written = path_to_be_written[1:]
                hashlist.append(((self.sha1(os.path.join(root, name)), os.path.join(path_to_be_written, name)))) # appends a new sha1 digest - file path tuple to the list
                    
        return hashlist

class Node:

    def __init__(self,title, date, file_name, url, kb):
        self.title = title
        self.date = date
        self.url = url
        self.kb = kb
        self.file_name = file_name
    
    def file_hash_from_url(self):
        file_name = self.file_name_from_url()
        hash = file_name.split('.')[0]
        return hash

    def file_name_from_url(self):
        base = self.url.split('?get=')[-1].decode('base64')
        return re.compile('(x64_|x86_)').split(base)[-1]
