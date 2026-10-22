# Third-party data / Dane zewnętrzne

`deploy/world.svg` is derived from Natural Earth 1:110m country polygons.
Natural Earth map data is public domain; no runtime map service is used.

`deploy/world.svg` powstał z konturów państw Natural Earth 1:110m.
Dane map Natural Earth są w domenie publicznej. Mapa nie korzysta z kafelków online.

- Terms / Warunki: https://www.naturalearthdata.com/about/terms-of-use/
- Source / Źródło: https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_admin_0_countries.geojson
- Downloaded source SHA256: `6866c877d39cba9c357620878839b336d569f8c662d3cfab4cb1dbe2d39c977f`
- Projection: equirectangular, 960 × 480, coordinates rounded to 0.1 px.
- Regenerate: `python3 tools/build_world.py PATH_TO_GEOJSON`.

Made with Natural Earth. Boundaries are cartographic data, not a statement of political status.
