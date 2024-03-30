
import route53
from attrs import define, validators, field
from loguru import logger
from typing import Any, List


lf="\n"
quote = '"'

def optquote(arg):
    ''' optionally add quotes '''
    arg = arg.strip()
    if arg[0] != quote:
        arg = quote + arg
    if arg[-1] != quote:
        arg += quote
    return arg

@define
class Route53(object):
    zoneid: str = field()
    domain: str = field()
    aws_access_key: str = field()
    aws_secret_access_key: str = field()
    rr_conn: Any = field(default=None)
    rr_zone: Any = field(default=None)
    rr_recs: dict = field(default={})

    def _connect(self):
        ''' ensure that we're connected '''
        if self.rr_conn:
            return
        logger.debug(f'Open credentialed connection to route53.')
        self.rr_conn = route53.connect( 
            aws_access_key_id = self.aws_access_key,
            aws_secret_access_key = self.aws_secret_access_key )
        return

    def _get_zone_data(self, refresh=False):
        ''' download the zone data '''
        if self.rr_zone and not refresh:
            return
        logger.debug(f'load zone {self.zoneid}.')
        try:
            self.rr_zone = self.rr_conn.get_hosted_zone_by_id(self.zoneid)
        except:
            logger.error(f'Failed to load zone: {self.zoneid}.')
            raise
        pass

    def _find_records(self, domainname):
        ''' look for one record in all records '''
        if domainname in self.rr_recs.keys():
            self._get_zone_data(True)

        logger.debug(f'search records for domain {domainname}.')
        for x in self.rr_zone.record_sets:
            if x.rrset_type == 'TXT' and domainname in x:
                logger.trace(f'located record: {x.name}')
                try:
                    self.rr_recs[domainname].append(x)
                except KeyError:
                    self.rr_recs[domainname] = [x]
                continue
            continue
        return

    def save_txt_record(self, hostname: str, data: list, commit=True):
        ''' commit host changes to zone '''
        self._connect()
        self._get_zone_data()
        self._find_records(hostname)

        record = None
        try:
            records = self.rr_recs[hostname]
            if len(records) > 1:
                for x in records:
                    logger.warning(f'Multiple records: {x}')
                    continue
                pass
            record = records[0]
        except:
            records = None

        newvalues = [ optquote(x) for x in data if x.strip() > '' ]
        if record:
            logger.trace(f'Update: replace{lf}    {record.records}{lf}with:{lf}    {newvalues}')
            if record.records == newvalues:
                logger.debug(f'No update needed {hostname}')
            else:
                record.records = newvalues
            if commit:
                record.save()
            else:
                logger.warning(f'Would have saved changes: {hostname} // {newvalues}.')
                pass
        else:
            logger.debug(f'create new host record')
            if commit:
                self.rr_zone.create_txt_record(hostname, newvalues)
            else:
                logger.error(f'Would have committed: {hostname} // {newvalues}')
                pass
            pass

        return True
