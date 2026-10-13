// Builds src/surya_kundal/dashboard/static/world.svg from Natural Earth data (public domain)
// via the world-atlas and us-atlas npm packages. It uses the same projection as
// dashboard.app.project(): equirectangular on a 960x480 canvas, so server-side dot
// positions line up with the map. Run: npm i world-atlas@2 us-atlas@3 topojson-client@3
// topojson-simplify@3 d3-geo@3 && node make_world_map.mjs world.svg
import { readFileSync, writeFileSync } from "node:fs";
import { geoEquirectangular, geoPath } from "d3-geo";
import { feature, mesh } from "topojson-client";
import { presimplify, quantile, simplify } from "topojson-simplify";

const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url)));
const thin = (topology, keep) => {
  const pre = presimplify(topology);
  return simplify(pre, quantile(pre, keep));
};
const world = thin(read("./node_modules/world-atlas/countries-50m.json"), 0.15);
const us = thin(read("./node_modules/us-atlas/states-10m.json"), 0.3);

const projection = geoEquirectangular().scale(960 / (2 * Math.PI)).translate([480, 240]);
const path = geoPath(projection).digits(1);

const land = path(feature(world, world.objects.land));
const borders = path(mesh(world, world.objects.countries, (a, b) => a !== b));
const states = path(mesh(us, us.objects.states, (a, b) => a !== b));

const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 480" preserveAspectRatio="xMidYMid meet">
<style>.land{fill:#D1D1D6}.border{fill:none;stroke:#F2F2F7;stroke-width:.5;stroke-linejoin:round}.state{fill:none;stroke:#F2F2F7;stroke-width:.3;stroke-linejoin:round}@media (prefers-color-scheme:dark){.land{fill:#3A3A3C}.border{stroke:#1C1C1E}.state{stroke:#1C1C1E}}</style>
<path class="land" d="${land}"/>
<path class="border" d="${borders}"/>
<path class="state" d="${states}"/>
</svg>
`;
writeFileSync(process.argv[2] ?? "world.svg", svg);
console.log(svg.length, "bytes");
