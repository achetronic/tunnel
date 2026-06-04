# Config transforms

`tunnelctl` can postprocess a desired-state document before applying it, using a CEL
rules file passed with `--transforms`. One shared config then renders differently per
node: each replica derives its own values from its environment.

A rule targets a path in the config and replaces its value with the result of a CEL
expression. The whole config is available to every expression as `config`. Rules run in
order, so a later rule sees an earlier rule's write. Expressions are
[CEL](https://github.com/google/cel-spec).

```yaml
transforms:
  - path: wireguard.interface.address
    expr: '"10.200.0.5/32"'
```

## Paths

A path is a dot-separated list of map keys and bracketed list indices. Missing
intermediate objects and lists are created on write.

```text
wireguard.interface.address      # a field
wireguard.peers[0].publicKey     # a list element's field
nftables.rules[2].targetPort     # nested list + field
matrix[0][1]                     # nested lists
```

```yaml
transforms:
  - path: a.b.c # {} becomes {"a":{"b":{"c": ...}}}
    expr: '"deep"'
  - path: items[1] # grows the list; index 0 is null
    expr: '"second"'
```

## Functions

Beyond the CEL standard library, the `strings` extension (`split`, `trim`, ...) and
`cel.bind`, these helpers are available:

| Function                | Result                                                                       |
| ----------------------- | ---------------------------------------------------------------------------- |
| `getenv(name)`          | environment variable value                                                   |
| `readFile(path)`        | file contents                                                                |
| `fromJSON(text)`        | value parsed from JSON                                                       |
| `fromYAML(text)`        | value parsed from YAML                                                       |
| `cidrHost(cidr, index)` | the index-th host of a CIDR, e.g. `cidrHost("10.0.0.0/24", 5)` is `10.0.0.5` |

## Examples

Copy another field of the config:

```yaml
transforms:
  - path: wireguard.peers[0].allowedIPs[0]
    expr: "config.wireguard.interface.address"
```

Compute a value from the environment:

```yaml
transforms:
  - path: wireguard.interface.address
    expr: |
      cel.bind(ord, int(getenv("ORDINAL")),
        cidrHost(config.nftables.tunnelNetwork, 2 + ord) + "/32")
```

Read a secret from a mounted file:

```yaml
transforms:
  - path: wireguard.interface.privateKey
    expr: 'readFile(getenv("KEYS_DIR") + "/priv-0").trim()'
```

Pull a key out of a JSON or YAML blob:

```yaml
transforms:
  - path: target.host
    expr: 'fromJSON(readFile("/etc/endpoints.json")).primary.host'
```

`uplink.transforms.yaml` in this directory is the live example: it gives every uplink
replica its own tunnel address and private key from the same shared document.
