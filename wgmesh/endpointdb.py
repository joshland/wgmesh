import socket
import attr
import uuid

from loguru import logger
from ruamel.yaml import YAML
from nacl.public import PublicKey

from .core import load_public_key, load_private_key, keyimport
from .version import VERSION

def nonone(arg):
    ''' eliminate the None and blanks '''
    if arg == None:
        return ''
    return arg

def validateHostname(value):
    if value == None:
        return socket.gethostname()
    return value

def validateUuid(value):
    if value == None:
        return str( uuid.uuid4() )
    return value

@attr.s
class Endpoint(object):
    hostname = attr.ib(default=None, kw_only=True, converter=validateHostname)
    uuid     = attr.ib(default=None, kw_only=True, converter=validateUuid)
    SSK      = attr.ib(default='',   kw_only=True)
    PPK      = attr.ib(default='',   kw_only=True)
    cmdfping    = attr.ib(default="/usr/sbin/fping",    kw_only=True, converter=str)
    private_key_file = attr.ib(default='', kw_only=True, converter=nonone)
    public_key_file  = attr.ib(default='', kw_only=True, converter=nonone)
    interface_public = attr.ib(default='', kw_only=True, converter=nonone)
    interface_trust  = attr.ib(default='', kw_only=True, converter=nonone)
    interface_trust_ip = attr.ib(default='', kw_only=True, converter=nonone)
    interface_outbound = attr.ib(default='', kw_only=True, converter=nonone)

    def publish(self):
        m2 = {attr: str(getattr(self, attr)) for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__")}
        logger.trace(f'publish dict: {m2}')
        del m2['SSK']
        del m2['PPK']
        return m2
    pass

@attr.s
class SiteDetail(object):
    locus      = attr.ib(default='', kw_only=True, converter=nonone)
    public_key = attr.ib(default='', kw_only=True, converter=nonone)
    PPK        = attr.ib(default='', kw_only=True)

    def publish(self):
        m2 = {attr: str(getattr(self, attr)) for attr in dir(self) if not callable(getattr(self, attr)) and not attr.startswith("__")}
        logger.trace(f'publish dict: {m2}')
        del m2['PPK']
        return m2
    pass

class HostDB(object):
    def __init__(self, filename, **kwargs):
        self.filename = filename
        self.host  = Endpoint(**kwargs.get('host', {}))
        self.site  = SiteDetail(**kwargs.get('site', {}))
        pass

    def publish(self):
        retval = {
            'host': self.host.publish(),
            'site': self.site.publish(),
        }
        logger.trace(f'publish dict: {retval}')
        return retval
    pass

def load_host_config(domain: str, locus: str, pubkey: str) -> str:
    ''' Load/Generate local site-base config

    opens /etc/wireguard/{locus}.yaml

    return
    '''
    fn = f'/etc/wireguard/{domain}.yaml'
    yaml = YAML(typ='rt')

    try:
        with open(fn) as yamlfile:
            config = yaml.load(yamlfile)
        baseconfig = False
    except FileNotFoundError:
        baseconfig = True
        config = {
            'site': {
                'locus': locus,
                'public_key': pubkey,
            },
        }
        pass

    retval = HostDB(fn, **config)

    return retval

def save_host_config(config: HostDB):
    ''' commit hostdb to disk '''
    filename = config.filename
    data = config.publish()
    yaml = YAML(typ='rt')
    ##leftoff - leave a way to update the file
    with open(filename, 'w') as yamlfile:
        yaml.dump(data, yamlfile)
        pass
    pass

def check_update_route_table(rt_id: int, name: str) -> bool:
    ''' check that rt_table {number} exists in /etc/iproute2/rt_tables '''
    rt_id = str(rt_id)
    with open('/etc/iproute2/rt_tables', 'r') as rtfile:
        content = rtfile.read().split('\n')
        pass

    decoded = [ x.split('\t') for x in content ]
    tables  = [ x[0] for x in decoded ]
    if rt_id in tables:
        idx = tables.index(rt_id)
        if decoded[idx][1] == name:
            logger.trace(f'Located {rt_id}=>{name} in rt_tables.')
            return False
        else:
            logger.trace(f'Updating name for {rt_id} - {decoded[idx][1]}=>{name}')
            decoded[idx][1] = name
            pass
    else:
        logger.trace(f'Adding route table: {rt_id} ({name})')
        decoded.insert(-1, (rt_id, name))
        pass

    content = [ '\t'.join(line) for line in decoded ]
    with open('/etc/iproute2/rt_tables', 'w') as rtfile:
        rtfile.write("\n".join(content))
        pass

    return True

def CheckLocalHostConfig(domain: str, locus: str, pubkey: str,
                         public: str = '', asn: str = '', 
                         trust: str = '', outbound: str = '',
                         trustip: str = '') -> str:
    ''' Load/Generate local site-base config

    Validate and update the settings.

    return
    '''

    config = load_host_config(domain, locus, pubkey)

    if outbound: config.host.interface_outbound = outbound
    if public:   config.host.interface_public   = public
    if trustip:  config.host.interface_trust_ip = trustip
    if trust:    config.host.interface_trust    = trust

    if config.host.private_key_file == '':
        config.host.private_key_file = f'/etc/wireguard/{locus}_priv'
        pass

    if config.host.public_key_file == '':
        config.host.public_key_file  = f'/etc/wireguard/{locus}_pub'
        pass

    try:
        SSK = load_private_key(config.host.private_key_file)
    except FileNotFoundError:
        logger.debug(f'Private key does not exist. {config.host.private_key_file}')
        SSK = None
        pass

    try:
        PPK = load_public_key(config.host.public_key_file)
    except FileNotFoundError:
        logger.debug(f'Public key does not exist. {config.host.public_key_file}')
        PPK = None
        pass

    #config.host.asn = 
    config.host.SSK = SSK
    config.host.PPK = PPK
    config.site.PPK = keyimport(config.site.public_key, PublicKey)

    save_host_config(config)

    return config

if __name__ == "__main__":
    from loguru import logger
    testkey = '2V4qw+wVPNlATGFE8DSc7S4FW+3p3AivgFBdQdKjkyY='
    hostdata = load_host_config('test.local.example', 'exampletest', testkey)
    save_host_config(hostdata)
    pass

