/* Native CyberBrief radar. Animates aggregate observations, never invented routes. */
(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const ns = 'http://www.w3.org/2000/svg';
  const number = value => Number(value || 0).toLocaleString();
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let geometry = [], telemetry = null, selected = null, loading = false;
  let paused = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
  const root = document.querySelector('.native-radar');
  function svg(tag, attributes) {
    const el = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attributes)) el.setAttribute(key, value);
    return el;
  }
  function setPaused(value) {
    paused = value;
    root.classList.toggle('animation-paused', paused);
    byId('radar-toggle').setAttribute('aria-pressed', String(paused));
    byId('radar-toggle').textContent = paused ? 'Resume animation' : 'Pause animation';
  }
  function select(code) {
    selected = selected === code ? null : code;
    render();
  }
  function ranking() {
    const rows = telemetry.rows || [], countries = telemetry.countries || [];
    if (selected) {
      const country = countries.find(c => c.code === selected);
      byId('radar-region-title').textContent = country?.name || selected;
      const ips = rows.filter(row => row.country_code === selected);
      byId('radar-region-count').textContent = `${ips.length} IPs`;
      byId('radar-ranking').innerHTML = `<div class="region-summary"><strong>${number(country?.reports)}</strong><span>reported packets in this sample</span></div>` + ips.map(row => `<a class="radar-ip" href="https://isc.sans.edu/ipinfo.html?ip=${encodeURIComponent(row.ip)}" target="_blank" rel="noopener noreferrer"><span>${esc(row.ip)}</span><strong>${number(row.reports)}</strong><small>${number(row.targets)} targets reported for this IP</small></a>`).join('');
    } else {
      byId('radar-region-title').textContent = 'Observed source regions';
      byId('radar-region-count').textContent = `${countries.length} total`;
      const max = Math.max(1, ...countries.map(c => c.reports));
      byId('radar-ranking').innerHTML = countries.slice(0, 6).map((country, i) => `<button class="region-row" type="button" data-country="${esc(country.code)}"><span class="region-position">${String(i + 1).padStart(2, '0')}</span><span class="region-name">${esc(country.name)}<svg class="region-bar" viewBox="0 0 100 2" aria-hidden="true"><rect width="100" height="2" class="bar-track"/><rect width="${Math.max(1, country.reports / max * 100).toFixed(2)}" height="2" class="bar-value"/></svg></span><strong>${number(country.reports)}</strong></button>`).join('') || '<p class="radar-empty">No mapped regions yet. Collected sources without geolocation remain in the totals.</p>';
    }
  }
  function render() {
    if (!telemetry) return;
    const countries = telemetry.countries || [];
    const max = Math.max(1, ...countries.map(c => c.reports));
    const lookup = new Map(countries.map(c => [c.code, c]));
    byId('radar-reports').textContent = number(telemetry.reports);
    byId('radar-ips').textContent = number(telemetry.rows?.length);
    byId('radar-countries').textContent = number(countries.length);
    const stale = telemetry.last_success && Date.now() - Date.parse(telemetry.last_success) > 7200000;
    byId('radar-status').textContent = telemetry.error ? 'Cached data · provider unavailable' : !telemetry.last_success ? (telemetry.refreshing ? 'Collecting public telemetry' : 'Awaiting telemetry') : stale ? 'Cached snapshot · collection overdue' : 'Public telemetry connected';
    byId('radar-status').classList.toggle('radar-warning', !!telemetry.error || !!stale);
    byId('radar-window').textContent = telemetry.last_success ? `Report window: ${telemetry.window} · checked ${new Date(telemetry.last_success).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}${telemetry.unmapped_sources ? ` · ${telemetry.unmapped_sources} unmapped IPs` : ''}` : telemetry.error || 'Waiting for the first successful collection';
    const layer = byId('map-countries'), pulses = byId('map-pulses');
    layer.replaceChildren(); pulses.replaceChildren();
    for (const country of geometry) {
      const report = lookup.get(country.code);
      const level = report ? Math.min(4, 1 + Math.floor(report.reports / max * 3)) : 0;
      const path = svg('path', {d:country.path, class:'country-shape', 'data-level':level, 'data-country':country.code, 'data-selected':String(selected === country.code)});
      const title = svg('title', {});
      title.textContent = `${country.name}: ${report ? number(report.reports) + ' reported packets' : 'no sources in this sample'}`;
      path.appendChild(title);
      if (report) {
        path.setAttribute('tabindex', '0'); path.setAttribute('role', 'button');
        path.setAttribute('aria-label', `Inspect ${country.name}, ${number(report.reports)} reported packets`);
        path.setAttribute('aria-pressed', String(selected === country.code));
      }
      layer.appendChild(path);
      if (report) {
        const dot = svg('g', {class:'radar-marker', transform:`translate(${country.x} ${country.y})`});
        dot.appendChild(svg('circle', {r:4 + Math.sqrt(report.reports / max) * 4, class:'marker-core'}));
        dot.appendChild(svg('circle', {r:9 + Math.sqrt(report.reports / max) * 6, class:'marker-pulse'}));
        pulses.appendChild(dot);
      }
    }
    if (selected && !lookup.has(selected)) selected = null;
    ranking();
  }
  async function refresh() {
    if (loading || document.hidden) return;
    loading = true;
    try {
      const response = await fetch('/api/radar');
      if (!response.ok) throw new Error('Telemetry unavailable');
      telemetry = await response.json(); render();
    } catch {
      byId('radar-status').textContent = 'Radar server unavailable';
      byId('radar-status').classList.add('radar-warning');
      if (!telemetry) byId('radar-ranking').innerHTML = '<p class="radar-empty">Public telemetry is unavailable. The map will retry automatically; no activity is simulated.</p>';
    } finally { loading = false; }
  }
  byId('radar-toggle').addEventListener('click', () => setPaused(!paused));
  byId('radar-reset').addEventListener('click', () => { selected = null; render(); });
  byId('radar-method').addEventListener('click', () => { const el = byId('radar-methodology'); el.hidden = !el.hidden; byId('radar-method').setAttribute('aria-expanded', String(!el.hidden)); });
  root.addEventListener('click', event => { const country = event.target.closest('[data-country]'); if (country && telemetry?.countries.some(c => c.code === country.dataset.country)) select(country.dataset.country); });
  byId('native-world').addEventListener('keydown', event => { if (['Enter', ' '].includes(event.key) && event.target.matches('[data-country]')) { event.preventDefault(); select(event.target.dataset.country); } });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  setPaused(paused);
  fetch('/world-map.json').then(response => { if (!response.ok) throw new Error(); return response.json(); }).then(world => { geometry = world.countries; render(); }).catch(() => { byId('radar-status').textContent = 'Map geometry unavailable'; });
  refresh(); setInterval(refresh, 60000);
})();
