# crl-monitor

`crl-monitor` is a small binary program that can monitor a list of CRLs, and expose their expiration date as Prometheus metrics.

To run, simply use:

```
 ./crl-monitor -config config.yaml
```

Where `config.yaml` contains the CRLDPs under the YAML key `crls`:

```yaml
crls:
  - http://crl.example.org/test.crl
```

