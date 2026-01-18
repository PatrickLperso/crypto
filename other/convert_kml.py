import json
import simplekml
import os 

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "datacenter_russia.geojson")


with open(path) as f:
    data = json.load(f)

kml = simplekml.Kml()
for feature in data['features']:
    if feature['geometry']['type'] == 'Polygon':
        kml.newpolygon(name=name,
                       description='test',
                       outerboundaryis=feature['geometry']['coordinates'][0])
    elif feature['geometry']['type'] == 'LineString':
        kml.newlinestring(name=name,
                          description='test',
                          coords=feature['geometry']['coordinates'])

    elif feature['geometry']['type'] == 'Point':
        kml.newpoint(name=feature["properties"]["title"].split("\n")[0].strip().replace("»", "").replace("«", ""),
                     description="\n".join(feature["properties"]["title"].split("\n")[1:]),
                     coords=[feature['geometry']['coordinates']])
kml.save('file.kml')