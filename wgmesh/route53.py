
import route53
import attr, inspect
from loguru import logger

CR="\n"

@attr.s
class Route53(object):
    sitecfg = attr.ib()
    rr_conn = attr.ib(default=None, kw_only=True)
    rr_zone = attr.ib(default=None, kw_only=True)
    rr_recs = attr.ib(default=[], kw_only=True)

    def save_txt_record(self, hostname: str, data: list, commit=True):
        ''' commit host changes to zone '''
        newvalues = [ f'"{x}"' for x in data if x.strip() > '' ]

        if not self.rr_conn:
            logger.debug(f'Open credentialed connection to route53.')
            self.rr_conn = route53.connect(
                aws_access_key_id = self.sitecfg.aws_access_key_id,
                aws_secret_access_key = self.site.aws_secret_access_key
            )
            pass

        if not self.rr_zone:
            logger.debug(f'open zone {self.sitecfg.route53}.')
            self.rr_zone = con.get_hosted_zone_by_id(self.sitecfg.route53)
            pass

        if not len(self.rr_recs):
            logger.debug(f'search records for domain {domain}.')
            for x in self.rr_zone.record_sets:
                if x.rrset_type == 'TXT' and x.name.find(domain) > -1:
                    logger.trace(f'located record: {x.name}')
                    self.domain_records.append(x)
                    continue
                continue
            pass

        record = None
        for x in self.domain_records:
            if x.name == hostname:
                record = x
                break
            continue

        if record:
            logger.trace(f'Update: replace{CR}    {record.records}{CR}with:{CR}    {newvalues}')
            if record.records == newvalues:
                logger.debug(f'No update needed {hostname}')
                pass
            record.records = newvalues
            print('Would')
            record.save()
        else:
            logger.debug(f'create new host record')
            self.rr_zone.create_txt_record(hostname, newvalues)


        return True
