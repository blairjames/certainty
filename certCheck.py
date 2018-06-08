#!/usr/bin/env python3

import OpenSSL
import certCheck_conf
import datetime
import det_gmail
import ssl
import toolbag
from typing import List, Dict


class CertCheckHTTPS:

    def __init__(self):
        self.gm: det_gmail = det_gmail.Gmail()
        self.tb: toolbag = toolbag.Toolbag()
        self.url_file: str = "/opt/certificate_check/master_list_external_domains.txt"
        self.logfile: str = self.tb.create_logfile("/opt/certificate_check/log/", "certmon")
        self.sorted_file: str = self.tb.create_logfile("/opt/certificate_check/log/", "certmon_sorted")
        self.day_dict: Dict = {}
        self.notsha256: List = []
        self.has_expired: List = []
        self.blacklist: List = certCheck_conf.blacklist

    def get_urls_from_file(self, dir: str) -> List:
        '''Read URLs from file in dir, parse into list, shuffle and return'''
        try:
            url_list = []
            dir: str = str(dir)
            with open(dir, "r") as url_file:
                for url in url_file.read().splitlines():
                    url_list.append(str(url))
                url_file.close()
            url_list = self.tb.shuffler(url_list)
            return url_list
        except IOError as i:
            print("IOError in CertCheckHTTPS.get_urls_from_file: " + str(i))
        except Exception as e:
            print("Error in CertCheckHTTPS.get_urls_from_file: " + str(e))

    def check_certificate(self, url: str):
        try:
            self.tb.lint("Checking " + str(url), self.logfile)
            dt = datetime.datetime
            cert = ssl.get_server_certificate((str(url), 443))
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            if (x509.has_expired()):
                self.expired(url)
            expdate_utc = dt.strptime(x509.get_notAfter().decode("ascii"), '%Y%m%d%H%M%SZ')
            self.days_left(self.cert_expiry_days(expdate_utc), url)
            self.is_hash_sha256(str(self.decoder(x509.get_signature_algorithm())), url)
        except Exception as e:
            print("Error in CertCheckHTTPS.check_certificate: " + str(e))

    def is_hash_sha256(self, hash: str, url: str) -> bool:
        try:
            if not "sha256" in str(hash):
                message = ("Warning! Certificate attached to " + str(url) + " is not using SHA256.")
                self.notsha256.append(str(url))
                self.tb.lint(str(message), self.logfile)
                return False
            else:
                return True
        except Exception as e:
            print("Error in CertCheckHTTPS.is_hash_sha256: " + str(e))

    def expired(self, url: str) -> bool:
        try:
            message = str(url) + " has expired."
            self.tb.lint(str(message), self.logfile)
            if str(url) not in self.has_expired:
                self.has_expired.append(str(url))
            return True
        except Exception as e:
            print("Error in CertCheckHTTPS.expired: " + str(e))

    def cert_expiry_days(self, expdate_utc: datetime) -> datetime:
        try:
            dt = datetime.datetime
            now = dt.utcnow()
            delta = expdate_utc - now
            days = delta.days
            return days
        except Exception as e:
            print("Error in CertCheckHTTPS.cert_expiry_days: " + str(e))

    def days_left(self, days: int, url: str) -> bool:
        try:
            if int(days) > 0:
                self.day_dict[str(url)] = int(days)
                self.tb.lint("\nCertificate attached to \"" + str(url) +
                             "\" expires in " + str(days) + " days.\n", self.logfile)
                return True
            else:
                self.expired(str(url))
                return False
        except Exception as e:
            print("Error in CertCheckHTTPS.days_left: " + str(e))

    def decoder(self, bytes: bytes) -> str:
        try:
            stringy = bytes.decode("utf-8")
            return str(stringy)
        except Exception as e:
            print("Error in CertCheckHTTPS.decoder: " + str(e))

    def mailer(self) -> bool:
        try:
            gm = det_gmail.Gmail()
            gm.sendFile("External Certificate Expiry Report", str(self.sorted_file))
            return True
        except Exception as e:
            print("Error in CertCheckHTTPS.mailer: " + str(e))

def main():
    try:
        c = CertCheckHTTPS()
        urls = c.get_urls_from_file(c.url_file)
        for url in urls:
            if str(url) in c.blacklist:
                continue
            else:
                c.check_certificate(url)

        #Take dict and sort via days left till exp into list using key -> value pairs.
        # We can then iterate as key -> value tuples ie "for url, days in sorty"
        sorty = [(k, c.day_dict[k]) for k in sorted(c.day_dict, key=c.day_dict.get, reverse=False)]

        def writer(message: str):
            try:
                with open(c.sorted_file, "a") as file:
                    file.write(str(message))
                    file.close()
            except Exception as e:
                print("Error in CertCheckHTTPS.main.writer: " + str(e))

        len256 = len(c.notsha256)
        if len256 > 0:
            writer("\nWarning! - " + str(len256) + " Certificates do not use SHA256.\n")
            for url in c.notsha256:
                writer("\nCertificate attached to \"" + str(url) + "\" does not use SHA256.\n")

        writer("\n")
        for url, days in sorty:
            if int(days) > 366:
                continue
            else:
                writer("\nCertificate attached to \"" + str(url) +
                       "\" expires in " + str(days) + " days.\n")

        for url in c.has_expired:
            writer("\nCertificate attached to \"" + str(url) + "\" has expired.\n")

        if not c.mailer():
            raise Exception

    except Exception as e:
        print("Error in CertCheckHTTPS.main: " + str(e))

if __name__ == '__main__':
    main()


