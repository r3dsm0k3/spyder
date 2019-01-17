from scraper import MsVNextScraper
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('--query', help="The query param to search for. Accepts a KB number or filename")
args = parser.parse_args()
query = args.query


if __name__ == '__main__':
    scraper = MsVNextScraper(query)
    scraper.find_matches()
    if len(scraper.nodes) > 0:
        scraper.download_matches()
        scraper.verify_downloaded_files()
    else:
        print 'Could not find a relevant ms update to download.'

