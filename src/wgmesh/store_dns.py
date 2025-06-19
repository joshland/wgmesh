#!/usr/bin/env python3
''' handle dns/route53 storage operations '''

from textwrap import wrap

import route53
from loguru import logger
from attrs import define, field

def convert_site_domain(arg):
    ''' add a '.' if needed '''
    if arg[-1] != '.':
         arg += '.'
    return arg

def domain_separator(hostname, domainname):
    split = hostname.find(domainname)
    uuid = hostname[:split].strip('.')
    domain = hostname[split:]
    return uuid, domain

@define
class DNSDataClass:
    zoneid: str = field()                  # Route53 Zone ID
    site_domain: str = field(converter=convert_site_domain) # Domain name of Site
    access: str = field()                # AWS Access Key
    secret: str = field()                # AWS Secret Access Key
    site_record: str = field(default='')
    zone_domain: str = field(default='') # Zone portion of site_domain, auto-detected
    records: list = field(default=[])    # Zone record from route53, for domain
    maps:    dict = field(default={})
    _conn: object = field(default=None)  # route53.connect object
    _zone: object = field(default=None)  # route53 Zone object

    @classmethod
    def openZone(cls, zoneid, domain, access, secret):
        ''' explicitly establish a connection with Route53 '''
        retval = cls(zoneid, domain, access, secret)
        retval.connect()
        return retval

    def connect(self):
        ''' setup conn with route53 '''
        logger.trace(f'Connect to AWS Zone: {self.zoneid}/{self.access}')
        self._conn = route53.connect(self.access, self.secret)
        logger.trace(f'Refreshed Hosted Zones: {self._conn}')
        for x in self._conn.list_hosted_zones():
            if x.id == self.zoneid:
                logger.trace(f'Locate Zone: {x.id}/{x.name}')
                self._zone = x
                self.zone_domain = x.name
                break
            logger.trace(f'Ignore Zone: {x.id}/{x.name}')
            continue

        if not self._zone:
            raise ValueError("No Valid AWS Zone Located")

        text_records = [ x for x in self._zone.record_sets if x.rrset_type == 'TXT' ]
        self.records = [ x for x in text_records if self.site_domain in x.name ]
        self.maps = {}
        for rrset in self.records:
            if self.site_domain == rrset.name:
                self.site_record = rrset
                continue
            uuid, domain = domain_separator(rrset.name, self.site_domain)
            size = sum([ len(x) for x in rrset.records ])
            logger.trace(f'Create Map: {uuid} => {rrset.name}({size})')
            self.maps[uuid] = rrset
            continue

    def chunk_data(self, payload):
        ''' split bas64 into chunked data that will fit into dns '''
        return [ f'"{i}:{x}"' for i, x in enumerate(wrap(payload, width=74)) if x > '' ]

    def write_site(self, payload: str) -> str:
        ''' write an updated site record '''
        if not self._conn:
            self.connect()

        chunked_data = self.chunk_data(payload)
        if self.site_record:
            if self.site_record.records != chunked_data:
                self.site_record.records = chunked_data
                body = self.site_record.save()
            else:
                logger.trace('Site data already correct, ignoring update')
                body = ''
        else:
            rrset, body = self._zone.create_txt_record(f'{self.site_domain}', chunked_data)
            logger.trace('Create site records: {rrset}')
            self.site_record = rrset
            pass
        return body


    def write_host(self, uuid: str, payload: str) -> str:
        ''' prepare and store a base64 encoded message in DNS '''
        if not self._conn:
            self.connect()

        chunked_data = self.chunk_data(payload)
        logger.trace(f'Encoded data for storage: {chunked_data}')
        logger.debug('Lookup for exinsting record: {str(uuid)}')
        record = self.maps.get(uuid, None)

        if record:
            logger.trace(f'Update Record {record.records} => [chunked data]')
            record.records = chunked_data
            body = record.save()
            logger.trace(f'DNS Response {body}')
            logger.debug('Committing to dns')
            logger.trace('AWS Record Save: {retval}')
        else:
            rrset, body = self._zone.create_txt_record(f'{uuid}.{self.site_domain}', chunked_data)
            logger.trace(f'Create Map: {uuid} => {rrset}')
            self.maps[uuid] = rrset
        return body

    def remove_host(self, uuid: str):
        ''' remove a particular record from dns '''
        rrset = self.maps[uuid]
        body = rrset.delete()
        return body
