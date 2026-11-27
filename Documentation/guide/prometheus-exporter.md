<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# NVMe Prometheus Exporter

The [NVMe Exporter](https://github.com/E4-Computer-Engineering/nvme-exporter)
allows you to export NVMe SMART and OCP SMART metrics in Prometheus format.

Aggregating these metrics makes it possible to resolve the drive endurance in
real time:

- [Write Amplification Factor](https://en.wikipedia.org/wiki/Write_amplification)
  for the current workload
- [TeraBytes Written](https://en.wikipedia.org/wiki/Solid-state_drive)
- Estimated Drive Remaining Life and its projection in X time given the current
  workload
- Calculation of a dynamic Drive Writes Per Day

These are just a few examples: by referring to the
[SNIA documentation](https://www.snia.org/sites/default/files/SSSI/NVMe_SAS_SATA_Endurance_White_Paper.pdf)
and customising the
[Prometheus rules](https://github.com/E4-Computer-Engineering/nvme-exporter/tree/main/resources/prom),
it is possible to
[visualize](https://github.com/E4-Computer-Engineering/nvme-exporter/blob/main/resources/grafana/nvme_endurance.png)
the effective utilization of NVMe drives for the given workload historically and
in real time.
