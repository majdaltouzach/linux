// SPDX-License-Identifier: GPL-2.0
/*
 * JARVIS System Monitor sub-module
 *
 * Provides real-time hardware metrics to the AI daemon so it can make
 * intelligent decisions about:
 *
 *   - Which LLM to run: if GPU VRAM is tight, use a smaller Ollama model or
 *     fall back to the cloud API (Claude, OpenAI, etc.)
 *   - Whether to throttle generation: if thermal_celsius > thermal_crit_c * 0.9
 *     the daemon should pause or reduce batch size
 *   - How much context the model can safely hold: bounded by mem_avail_mb
 *
 * Interface
 * ---------
 *   ioctl(fd, JARVIS_IOC_SYSMON, struct jarvis_sysmon *)  — one-shot snapshot
 *   /sys/class/misc/jarvis/sysmon/ attrs                   — individual attrs
 *     cpu_load   — CPU 1-min load average × 100
 *     cpu_count  — online CPU count
 *     mem_total  — total RAM MiB
 *     mem_avail  — available RAM MiB
 *     thermal    — "25 31 0 0 …" (temp per zone in °C, space-separated)
 *     thermal_crit — highest critical trip-point in °C
 *
 * Copyright (c) 2025 JARVISos Contributors
 */
#define pr_fmt(fmt) "jarvis-sysmon: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/sched/loadavg.h>
#include <linux/cpumask.h>
#include <linux/thermal.h>
#include <linux/uaccess.h>
#include <linux/seq_buf.h>

#include <uapi/linux/jarvis.h>
#include "jarvis_sysmon.h"

/* -----------------------------------------------------------------------
 * Core sampling helpers
 * --------------------------------------------------------------------- */

static void sample_cpu(struct jarvis_sysmon *s)
{
	/* avenrun[] is in fixed-point FSHIFT format; scale to ×100 */
	s->cpu_load_1min = (avenrun[0] * 100) >> FSHIFT;
	s->cpu_count     = num_online_cpus();
}

static void sample_memory(struct jarvis_sysmon *s)
{
	struct sysinfo si;
	si_meminfo(&si);

	/* si.mem_unit bytes per page unit */
	s->mem_total_mb = ((u64)si.totalram * si.mem_unit) >> 20;
	s->mem_free_mb  = ((u64)si.freeram  * si.mem_unit) >> 20;
	s->swap_total_mb = ((u64)si.totalswap * si.mem_unit) >> 20;
	s->swap_free_mb  = ((u64)si.freeswap  * si.mem_unit) >> 20;

	/* mem_avail ≈ free + reclaimable page-cache (stable since 4.1) */
	s->mem_avail_mb = (si_mem_available() * PAGE_SIZE) >> 20;
}

static void sample_thermal(struct jarvis_sysmon *s)
{
#ifdef CONFIG_THERMAL
	/*
	 * thermal_zone_get_zone_by_name() is the stable exported API for
	 * looking up a registered zone by its type string. There is no
	 * exported iterator for all zones from a module; probe well-known
	 * x86 zone names instead. Zones not present return ERR_PTR(-ENODEV).
	 */
	static const char * const known_zones[] = {
		"x86_pkg_temp", "acpitz", "k10temp", "coretemp",
		"pch_skylake", "pch_cannonlake", "pch_cometlake",
		"INT3400 Thermal", "B0D4", "B0D3",
		NULL
	};
	struct thermal_zone_device *tz;
	int idx = 0, i, temp, crit = 0;

	s->thermal_count = 0;
	memset(s->thermal_celsius, 0, sizeof(s->thermal_celsius));

	for (i = 0; known_zones[i] && idx < JARVIS_THERMAL_MAX_ZONES; i++) {
		tz = thermal_zone_get_zone_by_name(known_zones[i]);
		if (IS_ERR_OR_NULL(tz))
			continue;
		if (thermal_zone_get_temp(tz, &temp))
			continue;

		s->thermal_celsius[idx++] = temp / 1000;

		{
			int crit_temp;
			if (!thermal_zone_get_crit_temp(tz, &crit_temp) &&
			    crit_temp / 1000 > crit)
				crit = crit_temp / 1000;
		}
	}
	s->thermal_count = idx;
	s->thermal_crit_c = crit;
#else
	s->thermal_count  = 0;
	s->thermal_crit_c = 0;
#endif
}

/* -----------------------------------------------------------------------
 * Public API — called from jarvis_core.c ioctl handler
 * --------------------------------------------------------------------- */

void jarvis_sysmon_sample(struct jarvis_sysmon *s)
{
	memset(s, 0, sizeof(*s));
	sample_cpu(s);
	sample_memory(s);
	sample_thermal(s);
}

/* -----------------------------------------------------------------------
 * Sysfs attribute group "sysmon" on the misc device
 * --------------------------------------------------------------------- */

static ssize_t cpu_load_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct jarvis_sysmon s;
	jarvis_sysmon_sample(&s);
	return sysfs_emit(buf, "%u\n", s.cpu_load_1min);
}
static DEVICE_ATTR_RO(cpu_load);

static ssize_t cpu_count_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", num_online_cpus());
}
static DEVICE_ATTR_RO(cpu_count);

static ssize_t mem_total_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct jarvis_sysmon s;
	jarvis_sysmon_sample(&s);
	return sysfs_emit(buf, "%llu\n", s.mem_total_mb);
}
static DEVICE_ATTR_RO(mem_total);

static ssize_t mem_avail_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct jarvis_sysmon s;
	jarvis_sysmon_sample(&s);
	return sysfs_emit(buf, "%llu\n", s.mem_avail_mb);
}
static DEVICE_ATTR_RO(mem_avail);

static ssize_t thermal_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct jarvis_sysmon s;
	ssize_t len = 0;
	int i;

	jarvis_sysmon_sample(&s);
	for (i = 0; i < (int)s.thermal_count && i < JARVIS_THERMAL_MAX_ZONES; i++)
		len += sysfs_emit_at(buf, len, "%d ", s.thermal_celsius[i]);
	if (len > 0)
		buf[len - 1] = '\n';
	else
		len = sysfs_emit(buf, "\n");
	return len;
}
static DEVICE_ATTR_RO(thermal);

static ssize_t thermal_crit_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct jarvis_sysmon s;
	jarvis_sysmon_sample(&s);
	return sysfs_emit(buf, "%d\n", s.thermal_crit_c);
}
static DEVICE_ATTR_RO(thermal_crit);

static struct attribute *jarvis_sysmon_attrs[] = {
	&dev_attr_cpu_load.attr,
	&dev_attr_cpu_count.attr,
	&dev_attr_mem_total.attr,
	&dev_attr_mem_avail.attr,
	&dev_attr_thermal.attr,
	&dev_attr_thermal_crit.attr,
	NULL,
};

static const struct attribute_group jarvis_sysmon_attr_group = {
	.name  = "sysmon",
	.attrs = jarvis_sysmon_attrs,
};

/* -----------------------------------------------------------------------
 * Init / exit — called from jarvis_core
 * --------------------------------------------------------------------- */

int jarvis_sysmon_init(struct device *parent_dev)
{
	int rc = sysfs_create_group(&parent_dev->kobj, &jarvis_sysmon_attr_group);
	if (rc)
		pr_err("failed to create sysmon sysfs group: %d\n", rc);
	else
		pr_info("sysmon ready (cpu/memory/thermal metrics available)\n");
	return rc;
}

void jarvis_sysmon_exit(struct device *parent_dev)
{
	sysfs_remove_group(&parent_dev->kobj, &jarvis_sysmon_attr_group);
}
