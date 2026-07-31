# scripts

### USE AT YOUR OWN RISK (; 

## attach_private_network.sh

Scans a modem's AT command port for a list of PLMNs you're authorized
to use (e.g., private/test networks you operate) and attaches to
whichever one becomes visible first, retrying with backoff until
registration is confirmed.

```
./attach_private_network.sh "103824,001010" /dev/pts/1 20
```

- `PLMN_LIST` - comma-separated PLMN ids to watch for, tried in order each scan (default: `103824`)
- `AT_PORT` - modem AT command tty (default: `/dev/pts/1`)
- `MAX_ATTEMPTS` - give up after N scan/attach cycles (default: `0` = retry forever)
