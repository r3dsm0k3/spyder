# Spyder

A program to download the Windows updates from the [ms-vnext](http://ms-vnext.net/UpdateArchive/) website. Upon the successful download, the program will check the integrity of the downloaded file with trusted source/s.

*Features*

* Finds out the trust confidence in the file even *before* downloading.
* Downloads the file/s based on the KB number
* Downloads the file/s based on the file name
* Multi-process file downloads

*Requirements*

* python 2.x

#### Installation

TODO

#### Usage

```python
pip install -r requirements.tx

python spyder.py --query kb-number/filename
```

#### Example Usage

```sh
# TRUSTED DOWNLOADS
python spyder.py --query 3194343
Trust confidence is HIGH for Windows10.0-KB3194343-x64.msu
Trust confidence is HIGH for Windows10.0-KB3194343-x86.msu
Starting to download Windows10.0-KB3194343-x64.msu
Starting to download Windows10.0-KB3194343-x86.msu
Finished downloading Windows10.0-KB3194343-x86.msu
Finished downloading Windows10.0-KB3194343-x64.msu


File Windows10.0-KB3194343-x64.msu for KB3194343 can be trusted
Moved the Windows10.0-KB3194343-x64.msu file to ./downloads/trusted folder


File Windows10.0-KB3194343-x86.msu for KB3194343 can be trusted
Moved the Windows10.0-KB3194343-x86.msu file to ./downloads/trusted folder


# UNTRUSTED DOWNLOADS
$ python spyder.py --query Windows10.0-KB3199209-x86.msu

Trust confidence is LOW for Windows10.0-KB3199209-x86.msu. Potentially malicious file found. Downloading to untrusted

Starting to download Windows10.0-KB3199209-x86.msu
Finished downloading Windows10.0-KB3199209-x86.msu

Windows10.0-KB3199209-x86.msu is potentially malicious. It can be found in the ./downloads/untrusted folder for further analysis

```

Intially, spyder downloads the matching files into a folder called `downloads/untrusted` in the current working directory. After spyder has verified the file identity, it moves them over to `downloads/trusted`.