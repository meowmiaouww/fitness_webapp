window.addEventListener('DOMContentLoaded', () => {
let map, marker;
DG.then(function() {
  map = DG.map('map', {
    center: [55.751574, 37.573856], // Москва по умолчанию
    zoom: 12
  });
});

async function searchAddress() {
  const address = document.getElementById('search-input').value.trim();
  if (!address) return;
  // Замените YOUR_API_KEY на ваш 2GIS API-ключ
  const apiKey = '9c1ecbe1-0ae3-41db-ada1-04f46cbf201e';
  const url = `https://catalog.api.2gis.ru/3.0/items?q=${encodeURIComponent(address)}&fields=items.point&key=${apiKey}`;
  try {
    const resp = await fetch(url);
    const data = await resp.json();
    const items = data.result.items;
    if (items.length === 0) {
      alert('Адрес не найден');
      return;
    }
    const point = items[0].point;
    const coords = [point.lat, point.lon];
    if (marker) map.removeLayer(marker);
    marker = DG.marker(coords).addTo(map);
    map.setView(coords, 16);
  } catch (e) {
    console.error(e);
    alert('Ошибка при поиске адреса');
  }
}

// Привязываем события после загрузки DOM
window.addEventListener('DOMContentLoaded', () => {
  document.getElementById('search-button').addEventListener('click', searchAddress);
  document.getElementById('search-input').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      searchAddress();
    }
  });
});
});
