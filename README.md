## SMTP secure transport

smtpst is the client side part of a new Kopano service aimed at making self-hosting email easier and more secure.

### Install package and helpers

Some of the examples in this guide use the jq command, make sure its installed.

```bash
apt install jq
apt install kopano-smtpstd
```

The service will automatically start up and connect to the default provider.

### Setup / Status

The service uses Kopano licenses from `/etc/kopano/licenses` automatically (with `groupware` and/or `smtpst` claims).

Check the current status with the status command like this.

```bash
kopano-smtpstd status
```

```yaml
provider: https://dev.kopano.xyz
  connected: true
  licenses:
    - 5e3e3f8c1f07468a53696d3dd147e8a52c2f58f5e91d3602bde9eb33577c4d4a

session: Vxnr86eV4juN36aCUVwftZ
  expiration: 2021-04-19 10:57:01 +0000 UTC
  domains:
    - 2gh5sq481io3.dev.kopano.xyz

```

If there is a license, it will be used according to the claims and a session will show up which tells the domain(s) assigned to the current smtpstd instance.

If there is no session, make sure that a license is available in the license directory. The license directory is scanned every minute for license changes automatically.

For groupware licenses, you will get a random domain. For custom domains, you need a smtpst license which lists those custom domains in its claims as defined
[here](https://stash.kopano.io/projects/KGOL/repos/kustomer/browse/docs/kopano-licenses.md).

Random domains are locked to a session. If the session is lost, then also the random domain is locked and cannot be resumed any more. Sessions expire, and thus need to be refreshed regularly. Means keep the service and system running if you expect to keep a random domain.

#### Receiving email

Once a session with domains is established, your local instance automatically starts receiving mails delivered to any address for any of the domains listed per session.

Incoming mails will be forwarded to the local MTA (by default `127.0.0.1:25`).

Make sure that postfix is accepting incoming mails for all the domains for each smtpstd session as destination or virtual domains.

```bash
postconf -e virtual_mailbox_domains="$(kopano-smtpstd status --json |jq -r '.domains | join(" ")')"
postfix reload
```

Further action is required when you use an external LDAP server for the virtual users. For each domain, also the `mail` attribute in the LDAP tree must include a corresponding entry. Please consult the Kopano Groupware documentation for further instructions on setting up Postfix with LDAP.

##### Kopano Groupware LDAP mail attribute bulk change

The following command replaces all user mail attributes in the local LDAP server domain with the first domain reported by `kopano-smtpstd status`. Adapt as needed to your LDAP configuration.

```bash
(SECRET=secret DOMAIN=$(kopano-smtpstd status --json |jq -r '.domains[0]'); \
  ldapsearch -H ldapi:/// -x -D "cn=admin,dc=nodomain" -w $SECRET \
    -b "dc=nodomain" '(&(objectClass=posixAccount)(mail=*))' mail |
      sed "s/^\(mail: .*@\)\(.*\)/changetype: modify\nreplace: mail\n\1$DOMAIN\n/" |
        ldapmodify -H ldapi:/// -x -D "cn=admin,dc=nodomain" -w $SECRET)
```

You should then sync these changes with `kopano-admin --sync`.

#### Sending email

Set your postfix `relayhost` to relay all remote messages through the running smtpst service.

```bash
postconf -e relayhost=[127.0.0.1]:10025
postconf -e default_transport=smtp
postconf -e relay_transport=smtp
postfix reload
```

Outbound addresses (from) must be using one of the domains which are registered for the active smtpstd session otherwise they will be rejected.

### Extra goodies

To make the local SMTP routing go to a specific mailbox instead of the designated RCPTTO.

```bash
[Service]
SMTPST_DEV_RCPTTO=root@localhost
```
