# Ansible — Aegis-Gate WAF fleet deploy

Collapses the per-node deploy (build → template `waf.yaml` → onnxruntime/geoip/TLS →
run detached → verify) into one command. **Build-once-and-distribute:** the binary is
compiled once on the `builder` host and copied to every node (all nodes are the same
Ubuntu/glibc/arch here). Scope = **WAF node deploy** (not the infra services or LB).

## Layout
```
ansible.cfg            inventory.ini            site.yml
group_vars/all.yml     # all tunables (endpoints, features, secrets, trust, AI)
templates/             # waf.yaml.j2, waf.env.j2  (per-node config)
roles/waf_build/       # compile the binary ONCE on the builder
roles/waf_node/        # distribute binary + assets, template config, run, verify
```

## Prereqs
- **Control node = this infra host.** It's also the `builder` and a `waf` node
  (`ansible_connection=local`).
- **Key-based SSH** from here to the remote nodes (set `ansible_user` /
  `ansible_ssh_private_key_file` in `inventory.ini`). The infra node needs none.
- Ansible (no sudo): `conda create -n ansible -c conda-forge ansible -y` then
  `conda run -n ansible ansible-playbook …` (or `conda activate ansible`).
- Remote nodes already cloned the repo to `~/aegis-gate` (the `deploy_dir`).

## Run
```sh
cd deploy/ansible
conda run -n ansible ansible-playbook site.yml                 # whole fleet
conda run -n ansible ansible-playbook site.yml --limit waf-2   # one node
conda run -n ansible ansible-playbook site.yml --check         # dry run
conda run -n ansible ansible-playbook site.yml --tags verify   # re-run smoke tests
```

What a full run does, per node (idempotent — only drift changes, config/binary
changes trigger a restart):
1. **builder:** `cargo build … --features "{{ waf_features }}"` once.
2. distribute the binary; fetch onnxruntime `{{ ort_version }}`; copy AI model + geoip.
3. self-signed TLS cert with the node's IP in the SAN.
4. template `waf.yaml` (unique `node.id`, `accept_proxy`, `trusted_proxies`, redis/otel/
   upstreams) + `.env`.
5. start the WAF detached (pid → `run/waf.pid`); wait for `/healthz/ready`; assert
   legit→200 + SQLi→403.

`serial: 1` deploys one node at a time, so a bad config can't drop the whole fleet.

## Secrets
`group_vars/all.yml` ships DEV defaults. For real secrets, put `control_secret`,
`csrf_secret`, `dashboard_password_hash`, `llm_api_key` in an `ansible-vault` file and
run with `--ask-vault-pass`. The `csrf_secret` MUST be identical across nodes
(leaderless console SSO). `llm_api_key` falls back to each node's `LLM_API_KEY` env.

## Not covered (by design — this scope is WAF nodes only)
The observability agent, the native nginx LB, and the infra services (Redis/mock/
SigNoz) are still managed as before (`deploy/compose/*`, `deploy/nginx/native-lb.sh`).
After adding/removing a node, update the LB node list + reload. Easy to add as roles
later (`waf_observability`, `nginx_lb`) if you want to fold them in.
