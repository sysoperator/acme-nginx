import dns.tsigkeyring
import dns.rdatatype
import dns.query
import dns.update
from os import getenv


class Bind9(object):
    def __init__(self, keypath, log):
        self.key = self.get_key(keypath)
        self.log = log
        self.dns_server = getenv("DNS_SERVER")
        if not self.dns_server:
            raise Exception("DNS_SERVER not found in environment")

    def create_record(self, name, data, domain):
        """
         name: '_acme-challenge.example.com'
         data: '"some data"'
         domain: '*.example.com'
        """
        domain = domain.lstrip("*.").rstrip(".")
        record = []
        for part in name.split('.'):
            record.append(part)
            update = dns.update.Update(domain, keyring=self.key[0], keyname=self.key[1], keyalgorithm=self.key[2])
            update.replace('.'.join(record), 60, dns.rdatatype.TXT, f'"{data}"')
            response = dns.query.tcp(update, self.dns_server)
            rcode = response.rcode()
            rcode_text = dns.rcode.to_text(rcode)
            if rcode_text == 'NOERROR':
                break
            elif rcode_text == 'NOTAUTH':
                domain = '.'.join(domain.split('.')[1:])
                continue
            elif rcode_text != 'NOERROR':
                raise Exception(f"Creating record failed with {rcode_text}")
        return "{}.{}".format('.'.join(record), domain)

    def delete_record(self, record, domain):
        domain = domain.lstrip("*.").rstrip(".")
        name = record
        record = []
        for part in name.split('.'):
            record.append(part)
            update = dns.update.Update(domain, keyring=self.key[0], keyname=self.key[1], keyalgorithm=self.key[2])
            update.delete('.'.join(record), dns.rdatatype.TXT)
            response = dns.query.tcp(update, self.dns_server)
            rcode = response.rcode()
            rcode_text = dns.rcode.to_text(rcode)
            if rcode_text == 'NOERROR':
                break
            elif rcode_text == 'NOTAUTH' or rcode_text == 'REFUSED':
                domain = '.'.join(domain.split('.')[1:])
                continue
            elif rcode_text != 'NOERROR':
                raise Exception(f"Deleting record failed with {rcode_text}")

    def get_key(self, keypath):
        with open(keypath) as f:
            keyfile = f.read().splitlines()
        name = keyfile[0].rsplit(' ')[1].replace('"', '').strip()
        algo = keyfile[1].rsplit(' ')[1].replace(';', '').replace('-', '_').upper().strip()
        key = keyfile[2].rsplit(' ')[1].replace('}', '').replace(';', '').replace('"', '').strip()
        k = {name: key}
        try:
            keyring = dns.tsigkeyring.from_text(k)
        except:
            print(f"{k} is not a valid key. The file should be in DNS KEY record format. See dnssec-keygen(8)")
            exit()
        return [keyring, name, dns.tsig.__dict__[algo]]
