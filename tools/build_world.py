#!/usr/bin/env python3
"""Convert Natural Earth 110m GeoJSON into an offline equirectangular SVG."""
import argparse
import hashlib
import html
import json
from pathlib import Path
parser=argparse.ArgumentParser()
parser.add_argument('source',type=Path)
args=parser.parse_args()
raw=args.source.read_bytes(); data=json.loads(raw)
parts=['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 480"><title>World map — Natural Earth</title><rect width="960" height="480" fill="#071923"/>']
for feature in data['features']:
    geometry=feature['geometry']
    polygons=[geometry['coordinates']] if geometry['type']=='Polygon' else geometry['coordinates']
    commands=[]
    for polygon in polygons:
        for ring in polygon:
            for i,(lon,lat,*_) in enumerate(ring):
                commands.append(('M' if i==0 else 'L')+'%.1f,%.1f'%((lon+180)/360*960,(90-lat)/180*480))
            commands.append('Z')
    parts.append('<path fill="#193d43" stroke="#4b7778" stroke-width="0.5" fill-rule="evenodd" d="'+''.join(commands)+'"><title>'+html.escape(feature['properties'].get('NAME_EN',feature['properties']['NAME']))+'</title></path>')
parts.append('</svg>')
root=Path(__file__).resolve().parents[1]
(root/'deploy/world.svg').write_text(''.join(parts)+'\n')
print('Countries:',len(data['features']),'Source SHA256:',hashlib.sha256(raw).hexdigest())
