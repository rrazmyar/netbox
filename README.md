## Install Netbox on Ubuntu 22.04 with Active Directory integration :

```
sudo apt update
sudo apt install -y postgresql
```

Verify that you have installed PostgreSQL 12 or later:

```
psql -V
```
### Database Creation :

Create a database for NetBox and assign it a username and password for authentication. Start by invoking the PostgreSQL shell as the system Postgres user.

```
sudo -u postgres psql
```

Within the shell, enter the following commands to create the database and user (role), substituting your own value for the password:

```
CREATE DATABASE netbox;
CREATE USER netbox WITH PASSWORD 'MyP@ssword';
ALTER DATABASE netbox OWNER TO netbox;
-- the next two commands are needed on PostgreSQL 15 and later
\connect netbox;
GRANT CREATE ON SCHEMA public TO netbox;
```

Once complete, enter \q to exit the PostgreSQL shell.

### Alter postgres hba.conf :

```
sudo vim /etc/postgresql/[version]/main/pg_hba.conf
```
```
# "local" is for Unix domain socket connections only
local   all             all                                     peer # <--Repalce With md5
# IPv4 local connections:
host    all             all             127.0.0.1/32            scram-sha-256 # <--Repalce With md5
# IPv6 local connections:
host    all             all             ::1/128                 scram-sha-256 # <--Repalce With md5
```

Restart postgres Service

```
sudo systemctl restart postgresql
```

### Verify Service Status :

```
$ psql --username netbox --password --host localhost netbox
Password for user netbox: 
psql (12.5 (Ubuntu 12.5-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

netbox=> \conninfo
You are connected to database "netbox" as user "netbox" on host "localhost" (address "127.0.0.1") at port "5432".
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
netbox=> \q
```

### Install Redis :

```
sudo apt install -y redis-server
```

Before continuing, verify that your installed version of Redis is at least v4.0:

```
redis-server -v
```


### Verify Service Status :

```
redis-cli ping
```
If successful, you should receive a ```PONG``` response from the server.

### Install System Packages :

Begin by installing all system packages required by NetBox and its dependencies.

```
sudo apt install -y python3 python3-pip python3-venv python3-dev build-essential libxml2-dev libxslt1-dev libffi-dev libpq-dev libssl-dev zlib1g-dev
```

Before continuing, check that your installed Python version is at least 3.10:

```
python3 -V
```

### Clone the Git Repository :

Create the base directory for the NetBox installation. For this guide, we'll use ```/opt/netbox```.

```
sudo apt install -y git
```

Clone the master branch of the NetBox GitHub repository into the current directory.

```
sudo git clone -b master --depth 1 https://github.com/netbox-community/netbox.git.
```

### Create the NetBox System User :

```
sudo adduser --system --group netbox
sudo chown --recursive netbox /opt/netbox/netbox/media/
sudo chown --recursive netbox /opt/netbox/netbox/reports/
sudo chown --recursive netbox /opt/netbox/netbox/scripts/
```

### Configuration :

Move into the NetBox configuration directory and make a copy of ```configuration_example.py``` named ```configuration.py```.This file will hold all of your local configuration parameters.

```
cd /opt/netbox/netbox/netbox/
sudo cp configuration_example.py configuration.py
```

```vim configuration.py``` following four are required for new installations:

* ```ALLOWED_HOSTS```
* ```DATABASE```
* ```REDIS```
* ```SECRET_KEY```


### ALLOWED_HOSTS :

This is a list of the valid hostnames and IP addresses by which this server can be reached. You must specify at least one name or IP address.

```
ALLOWED_HOSTS = ['netbox.example.com', '192.168.0.10']
```

If you are not yet sure what the domain name and/or IP address of the NetBox installation will be, you can set this to ```ALLOWED_HOSTS = ['*']```

### DATABASE :

You must define the username and password used when you configured PostgreSQL

```
DATABASE = {
    'NAME': 'netbox',               # Database name
    'USER': 'netbox',               # PostgreSQL username
    'PASSWORD': 'MyP@ssword',       # PostgreSQL password
    'HOST': 'localhost',            # Database server
    'PORT': '',                     # Database port (leave blank for default)
    'CONN_MAX_AGE': 300,            # Max database connection age (seconds)
}
```
         
### REDIS : 

```
REDIS = {
    'tasks': {
        'HOST': 'localhost',      # Redis server
        'PORT': 6379,             # Redis port
        'PASSWORD': '',           # Redis password (optional)
        'DATABASE': 0,            # Database ID
        'SSL': False,             # Use SSL (optional)
    },
    'caching': {
        'HOST': 'localhost',
        'PORT': 6379,
        'PASSWORD': '',
        'DATABASE': 1,            # Unique ID for second database
        'SSL': False,
    }
}
```

### SECRET_KEY :

A simple Python script named ```generate_secret_key.py``` is provided in the parent directory to assist in generating a suitable key:

```
python3 ../generate_secret_key.py
```

### Run the Upgrade Script :

```
sudo /opt/netbox/upgrade.sh
```

### Create a Super User :

Enter the Python virtual environment created by the upgrade script:

```
source /opt/netbox/venv/bin/activate
```

Next, we'll create a superuser

```
cd /opt/netbox/netbox
python3 manage.py createsuperuser
```

### Schedule the Housekeeping Task :

Management command that handles some recurring cleanup tasks, such as clearing out old sessions and expired change records.

```
sudo ln -s /opt/netbox/contrib/netbox-housekeeping.sh /etc/cron.daily/netbox-housekeeping
```

### Test the Application :

```
python3 manage.py runserver 0.0.0.0:8000 --insecure
```

Connect to the name or IP of the server on port 8000:

```
http://192.168.0.10:8000/
```

### install and configure gunicorn :

```
sudo cp /opt/netbox/contrib/gunicorn.py /opt/netbox/gunicorn.py
```

### systemd Setup :

We'll use systemd to control both gunicorn and NetBox's background worker process:

```
sudo cp -v /opt/netbox/contrib/*.service /etc/systemd/system/
sudo systemctl daemon-reload
```

Then, start the ```netbox``` and ```netbox-rq``` services and enable them to initiate at boot time:

```
sudo systemctl enable --now netbox netbox-rq
```

```
systemctl status netbox.service
```


# LDAP Configuration :

### Install System Packages :

```
sudo apt install -y libldap2-dev libsasl2-dev libssl-dev
```

### Install django-auth-ldap :

```
source /opt/netbox/venv/bin/activate
pip3 install django-auth-ldap
```

add the package to ```local_requirements.txt``` to ensure it is re-installed during future rebuilds of the virtual environment:

```
sudo sh -c "echo 'django-auth-ldap' >> /opt/netbox/local_requirements.txt"
```

### Configuration :

``` vim configuration.py ```

```
REMOTE_AUTH_BACKEND = 'netbox.authentication.LDAPBackend'
```
### General ```ldap_config.py``` Configuration :

Create ```netbox``` service account in active directory.
Create three group in active directory for netbox:

 * ```netbox-active```
 * ```netbox-staff```
 * ```netbox-superuser```

```netbox``` service account should be memeber of AD group ```netbox-active``` and ```netbox-superuser```


```
import ldap
from django_auth_ldap.config import LDAPSearch, NestedGroupOfNamesType

# Server URI
AUTH_LDAP_SERVER_URI = "ldap://domain.example.com:3268"

# The following may be needed if you are binding to Active Directory.
AUTH_LDAP_CONNECTION_OPTIONS = {
    ldap.OPT_REFERRALS: 0
}

# Set the DN and password for the NetBox service account.
AUTH_LDAP_BIND_DN = "cn=netbox,ou=ADGroup,dc=example,dc=com"
AUTH_LDAP_BIND_PASSWORD = "myService@ccountP@ssword" # Password for netbox Service Account in the Active Directory

# Include this setting if you want to ignore certificate errors. This might be needed to accept a self-signed cert.
# Note that this is a NetBox-specific setting which sets:
#     ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
LDAP_IGNORE_CERT_ERRORS = True

# Include this setting if you want to validate the LDAP server certificates against a CA certificate directory on your server
# Note that this is a NetBox-specific setting which sets:
#     ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, LDAP_CA_CERT_DIR)
# LDAP_CA_CERT_DIR = '/etc/ssl/certs'

# Include this setting if you want to validate the LDAP server certificates against your own CA.
# Note that this is a NetBox-specific setting which sets:
#     ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, LDAP_CA_CERT_FILE)
#LDAP_CA_CERT_FILE = '/path/to/example-CA.crt'

# This search matches users with the sAMAccountName equal to the provided username. This is required if the user's
# username is not in their DN (Active Directory).
AUTH_LDAP_USER_SEARCH = LDAPSearch(
    "dc=example,dc=com",
    ldap.SCOPE_SUBTREE,
    "(|(userPrincipalName=%(user)s)(sAMAccountName=%(user)s))"
)

# If a user's DN is producible from their username, we don't need to search.
AUTH_LDAP_USER_DN_TEMPLATE = None

# You can map user attributes to Django attributes as so.
AUTH_LDAP_USER_ATTR_MAP = {
    "username": "sAMAccountName",
    "email": "mail",
    "first_name": "givenName",
    "last_name": "sn",
}

AUTH_LDAP_USER_QUERY_FIELD = "username"

# This search ought to return all groups to which the user belongs. django_auth_ldap uses this to determine group
# hierarchy.
AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
    "dc=example,dc=com",
    ldap.SCOPE_SUBTREE,
    "(objectClass=group)"
)
AUTH_LDAP_GROUP_TYPE = NestedGroupOfNamesType()

# Define a group required to login.
AUTH_LDAP_REQUIRE_GROUP = "cn=netbox-active,ou=ADGroup,dc=example,dc=com"

# Mirror LDAP group assignments.
AUTH_LDAP_MIRROR_GROUPS = True

# Define special user types using groups. Exercise great caution when assigning superuser status.
AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    "is_active": "cn=netbox-active,ou=ADGroup,dc=example,dc=com",
    "is_staff": "cn=netbox-staff,ou=ADGroup,dc=example,dc=com",
    "is_superuser": "cn=netbox-superuser,ou=ADGroup,dc=example,dc=com"
}

# For more granular permissions, we can map LDAP groups to Django groups.
AUTH_LDAP_FIND_GROUP_PERMS = True

# Cache groups for one hour to reduce LDAP traffic
AUTH_LDAP_CACHE_TIMEOUT = 3600
AUTH_LDAP_ALWAYS_UPDATE_USER = True


```

