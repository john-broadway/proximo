# Check when node certificates expire

plane: pve

Reads only: never write. Lists: read plain first, and an empty list ends there (fields= on an empty list is refused). Otherwise read again with the fields named. An answer that fails, is refused, or is cut (truncated, or summarized with no data) is unread.

1. GET /nodes (fields=node,status). Each offline node is unread.
2. For each online {node}: GET /nodes/{node}/time (fields=time) for now. GET /nodes/{node}/certificates/info (fields=filename,notafter,subject). Unread: that node is unknown.
3. Days left = (notafter minus now) / 86400. Flag a certificate with fewer than the operator's days (30 if none given); expired if below 0. pve-root-ca.pem is the cluster CA. The web UI serves pveproxy-ssl.pem if present, else pve-ssl.pem.
4. GET /nodes/{node}/config, plain. An acme key: ACME is set up for the web UI certificate (renewal not proven; it does not cover the CA). No acme key: not set up. Unread: renewal unknown.

Report per node: each certificate, days left, flagged or not, which one the UI serves, and whether ACME is set up for it. Renewing (pvecm updatecerts, or ACME) is the operator's, on the node.
