# worm

---

worm.py developed of a poc of a self replicating cryptographic ransomware 

There is no reason to this project but simply educate developers
how to weaponize software in the name of science and software security,
so we could spread the art of software development growing community



## The `.wormconfig` file:

---
The file is based on a `key/value` pair external configuration.

The `default` value set to the `feild(defualt=...)` value of the  `WormConfig` module.

```text
key default
scan ./tests
ip_local default
ip_resolver default
```
Setting up `.wormconfig` file is easy. 
* `key` -> a 16bytes key
* `scan` -> a path in the OS we want to run our malware
* `ip_local` -> the private ip of the host
* `ip_resolver` -> an endpoint resolver to your public ip and geoip information of the host
