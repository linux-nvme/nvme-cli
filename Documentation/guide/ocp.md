<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# OCP documentation

"OCP" here means the Open Compute Project's Datacenter NVMe SSD Specification.
It defines vendor-specific log pages and Features on top of the base NVMe
specification, for things a hyperscale datacenter needs that the base spec does
not cover: extended SMART data, firmware activation history, latency monitoring,
telemetry string logs, and more.

## nvme-cli support

nvme-cli implements this specification in the `nvme ocp` plugin. It has more
than two dozen subcommands, covering most of the logs and Features the
specification defines. Run `nvme ocp --help` for the full list, or see the man
pages under
[`Documentation/nvme-ocp-*.txt`](https://github.com/linux-nvme/nvme-cli/tree/master/Documentation)
in the nvme-cli source for each one.

Examples:

```bash
$ nvme ocp smart-add-log /dev/nvme0        # extended SMART log
$ nvme ocp latency-monitor-log /dev/nvme0  # latency monitor log
$ nvme ocp fw-activate-history /dev/nvme0
```

## Specification links

* v1.0.3:
  https://www.opencompute.org/documents/nvme-cloud-ssd-specification-v1-0-3-pdf
* v2.0 r21:
  https://www.opencompute.org/documents/datacenter-nvme-ssd-specification-v2-0r21-pdf
* v2.5:
  https://www.opencompute.org/documents/datacenter-nvme-ssd-specification-v2-5-pdf
* v2.6.2:
  https://www.opencompute.org/documents/datacenter-nvme-ssd-specification-v2-6-2-pdf
* v2.7:
  https://www.opencompute.org/documents/datacenter-nvme-ssd-specification-v2-7-final-pdf-1

Each version is a full replacement of the previous one, not a diff. Check the
revision history inside the PDF itself for what changed between versions.

## OCP Storage Tech Talk

* 2024 OCP Storage Tech Talk:
  https://www.opencompute.org/events/past-events/2024-ocp-storage-tech-talk
