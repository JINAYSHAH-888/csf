"""Prometheus metrics module: correct exposition format."""

from __future__ import annotations

from csf.metrics import Counter, Gauge, Histogram, Registry


def test_counter_renders_total_with_labels():
    c = Counter("csf_x", "help")
    c.inc(decision="block")
    c.inc(decision="allow")
    c.inc(decision="allow")
    out = Registry_with(c).render()
    assert "# TYPE csf_x counter" in out
    assert 'csf_x_total{decision="allow"} 2' in out
    assert 'csf_x_total{decision="block"} 1' in out


def test_empty_counter_renders_zero():
    assert "csf_y_total 0" in Registry_with(Counter("csf_y", "h")).render()


def test_gauge_set_overwrites():
    g = Gauge("csf_g", "h")
    g.set(5.0)
    g.set(2.0)
    assert "csf_g 2" in Registry_with(g).render()


def test_histogram_buckets_are_cumulative_and_valid():
    h = Histogram("csf_d", "h", buckets=(0.001, 0.01, 0.1))
    for v in (0.0005, 0.005, 0.05, 0.5):
        h.observe(v)
    out = Registry_with(h).render()
    # cumulative: <=0.001 has 1, <=0.01 has 2, <=0.1 has 3, +Inf has 4
    assert 'csf_d_bucket{le="0.001"} 1' in out
    assert 'csf_d_bucket{le="0.01"} 2' in out
    assert 'csf_d_bucket{le="0.1"} 3' in out
    assert 'csf_d_bucket{le="+Inf"} 4' in out
    assert "csf_d_count 4" in out
    assert "csf_d_sum 0.5555" in out


def test_label_values_are_escaped():
    c = Counter("csf_z", "h")
    c.inc(reason='a"b\\c')
    out = Registry_with(c).render()
    assert '\\"' in out and '\\\\' in out


def Registry_with(metric):  # noqa: N802 - test helper
    r = Registry()
    r.register(metric)
    return r
