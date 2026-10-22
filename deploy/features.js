(() => {
  const svg = document.getElementById('world-map');
  if (!svg) return;
  const range = document.getElementById('map-range');
  const hour = document.getElementById('map-hour');
  const status = document.getElementById('map-status');
  const dots = document.getElementById('map-dots');
  const button = document.getElementById('map-play');
  let points = [], timer = null;
  function draw() {
    hour.textContent = range.value + ':59';
    const cells = new Map();
    for (const point of points) {
      if (point.hour > Number(range.value)) continue;
      const key = Math.floor(point.lat / 5) + ',' + Math.floor(point.lon / 5);
      if (!cells.has(key)) cells.set(key, {lat: 0, lon: 0, count: 0, ips: new Set(), countries: new Set()});
      const cell = cells.get(key);
      cell.lat += point.lat * point.count; cell.lon += point.lon * point.count;
      cell.count += point.count; cell.ips.add(point.ip); cell.countries.add(point.country);
    }
    dots.replaceChildren();
    let total = 0;
    for (const cell of cells.values()) {
      const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      dot.setAttribute('cx', String((cell.lon / cell.count + 180) / 360 * 960));
      dot.setAttribute('cy', String((90 - cell.lat / cell.count) / 180 * 480));
      dot.setAttribute('r', String(Math.min(17, 3 + Math.log2(cell.count + 1))));
      dot.setAttribute('fill', '#58f7a7'); dot.setAttribute('fill-opacity', '0.8');
      const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
      title.textContent = [...cell.countries].join(', ') + ' · ' + cell.count + ' żądań · ' + cell.ips.size + ' IP';
      dot.append(title); dots.append(dot); total += cell.count;
    }
    status.textContent = `${total} zlokalizowanych żądań · ${cells.size} grup na mapie · do ${range.value}:59`;
  }
  range.addEventListener('input', draw);
  button.addEventListener('click', () => {
    if (timer) { clearInterval(timer); timer = null; button.textContent = '▶ Odtwórz dzień'; return; }
    range.value = '0'; draw(); button.textContent = '⏸ Zatrzymaj';
    timer = setInterval(() => {
      if (Number(range.value) >= 23 || document.hidden) { clearInterval(timer); timer = null; button.textContent = '▶ Odtwórz dzień'; return; }
      range.value = String(Number(range.value) + 1); draw();
    }, 800);
  });
  const source = svg.dataset.source;
  const day = new URLSearchParams(location.search).get('day');
  const url = source + (day && source !== '/demo/data' ? '?day=' + encodeURIComponent(day) : '');
  function load() { return fetch(url, {credentials: 'same-origin', cache: 'no-store'})
    .then(response => { if (!response.ok) throw new Error('HTTP ' + response.status); return response.json(); })
    .then(data => { points = data.points; draw(); })
    .catch(() => { status.textContent = 'Nie udało się wczytać danych mapy. Sprawdź połączenie i datę.'; }); }
  load();
  if (source !== '/demo/data') setInterval(() => { if (!document.hidden) load(); }, 30000);
})();
