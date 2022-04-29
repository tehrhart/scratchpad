# -*- coding: utf-8 -*-
"""Sentinel Sat Coverage Finder.ipynb

This code is for quickly finding recent coverage around a given target coordinate.

Created by Tim Ehrhart (tehrhart@gmail.com)

"""
"""Key: (approximate resolutions and costs per km2)
Sentinel-2 10.0m     (free)       
Planet      3.0m  EUR  2.50/km2   (Available via SkyWatch)
SPOT        1.5m  EUR  0.70/km2   (cheapest via SentinelHub)
TripleSat   0.8m  EUR 10.00/km2   (Available via SkyWatch)
Satellogic  0.7m     (free)/km2   (Free via the Ukraine Observer platform)
PHR         0.5m  EUR  8.00/km2   (PHR is Airbus Pleiades, cheapest via SentinelHub)
SkySat      0.5m  EUR 10.00/km2   (Available via SkyWatch)
MAXAR       0.5m  EUR 16.50/km2   (Resampled from 0.3 to 0.5, minimum 5km2 purchase)
"""

#!pip3 install geopandas

#Login
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session
import geopandas as gpd
from shapely.geometry import Polygon, Point
import json, requests
from datetime import datetime, timedelta
import time

# Google Maps API Key
googleMapsKey = "XXXXXXXXXXXXXXXXXXXXXXXXXXX"

# Skywatch client credentials (API key)
sw_url = "https://api.skywatch.co/earthcache"
sw_key = "XXXXXXXXXXXXXXXXXXXXXXXXXXX"

# SentinelHub client credentials
client_id = 'XXXXXXXXXXXXXXXXXXXXXXXXXXX'
client_secret = 'XXXXXXXXXXXXXXXXXXXXXXXXXXX'

# Create a session
client = BackendApplicationClient(client_id=client_id)
oauth = OAuth2Session(client=client)

# Get token for the session
token = oauth.fetch_token(token_url='https://services.sentinel-hub.com/oauth/token',
                          client_secret=client_secret)

def getNameFromLatLon(lat,lon):
  #Fastest way to get a resonable name from a lat and lon
  geoURL = "https://maps.googleapis.com/maps/api/geocode/json?latlng={},{}&sensor=true&key={}".format(lat,lon,googleMapsKey)
  response = requests.get(geoURL)
  j = response.json()
  return j['plus_code']['compound_code']

def getBboxFromPoint(x,y,size=5010):
  #For Maxar and Planet searches
  #size = 5000 meters by default
  crs = ('EPSG:4326')
  s = gpd.GeoSeries([Point(x,y)], crs=crs)
  b = s.to_crs(epsg=900913).buffer((size/2)+1).to_crs(epsg=4326)
  j = json.loads(b.to_json())
  return(str(j['features'][0]['bbox']))

def getCoordCircleFromPoint(x,y,size=5010):
  #For Airbus searches
  #size = 5000 meters by default
  crs = ('EPSG:4326')
  s = gpd.GeoSeries([Point(x,y)], crs=crs)
  b = s.to_crs(epsg=900913).buffer((size/2)+1).to_crs(epsg=4326)
  j = json.loads(b.to_json())
  return(json.dumps(j['features'][0]['geometry']['coordinates']))

def planetSearch(lat, lon, spacecraft, startDate, endDate):
  bbox = getBboxFromPoint(lon, lat)
  searchURL = "https://services.sentinel-hub.com/api/v1/dataimport/search"
  headers = {'Content-type': 'application/json'}
  payload = """
  {
    "provider": "PLANET",
    "bounds": {
      "bbox": %s
    },
    "data": [
      {
        "itemType": "PSScene",
        "productBundle": "analytic_sr_udm2",
        "dataFilter": {
          "timeRange": {
            "from": "%s",
            "to": "%s"
          },
          "maxCloudCoverage": 80
        }
      }
    ]
  }""" % (bbox, startDate, endDate)
  resp = oauth.post(searchURL, data=payload, headers=headers)
  j = json.loads(resp.text)
  results = []
  if (len(j['features']) > 0):
    for f in j['features']:
      results.append(f['properties']['acquired'])
  else:
    results = []

  return results

def maxarSearch(lat, lon, spacecraft, startDate, endDate):
  bbox = getBboxFromPoint(lon, lat)
  searchURL = "https://services.sentinel-hub.com/api/v1/dataimport/search"
  headers = {'Content-type': 'application/json'}
  payload = """{
    "provider": "MAXAR",
    "bounds": {
      "bbox": %s
    },
    "data": [
      {
        "dataFilter": {
          "timeRange": {
            "from": "%s",
            "to": "%s"
          }
        },
        "productBands": "4BB",
        "productKernel": "CC"
      }
    ]
    }""" % (bbox, startDate, endDate)
  resp = oauth.post(searchURL, data=payload, headers=headers)
  j = json.loads(resp.text)
  results = []
  if (len(j['features']) > 0):
    for f in j['features']:
      results.append(f['acquisitionDateStart'])
  else:
    results = []
  #print("MAXAR: {}".format(results))
  return results

def airbusSearch(lat, lon, spacecraft, startDate, endDate):
  coords = getCoordCircleFromPoint(lon, lat)
  searchURL = "https://services.sentinel-hub.com/api/v1/dataimport/search"
  headers = {'Content-type': 'application/json'}
  payload = """{
    "provider": "AIRBUS",
    "bounds": {
      "geometry": {
        "type": "MultiPolygon",
        "coordinates": [%s]
      }
    },
    "data": [
      {
        "constellation": "%s",
        "dataFilter": {
          "maxCloudCoverage": 80,
          "timeRange": {
            "from": "%s",
            "to": "%s"
          }
        }
      }
    ]
  }""" % (coords,spacecraft,startDate,endDate)

  resp = oauth.post(searchURL, data=payload, headers=headers)
  j = json.loads(resp.text)
  results = []
  if (j['totalResults'] > 0):
    for f in j['features']:
      results.append(f['properties']['acquisitionDate'])
  else:
    results = []

  return results

def imageSearch(lat, lon, spacecraft, startDate, endDate):
  if spacecraft in ("SPOT","PHR"):
    return airbusSearch(lat, lon, spacecraft, startDate, endDate)
  elif spacecraft in ("MAXAR"):
    return maxarSearch(lat, lon, spacecraft, startDate, endDate)
  elif spacecraft in ("PLANET"):
    return planetSearch(lat, lon, spacecraft, startDate, endDate)
  else:
    return []

def skywatchSearch(lat, lon, startDate, endDate):
  #lat, lon = 47.82658, 37.70989
  startDate = startDate[:10]
  endDate = endDate[:10]
  headers = {'x-api-key': sw_key}
  sw_request = sw_url + "/archive/search"
  coords = getCoordCircleFromPoint(lon, lat)

  data = """{
    "location": {
      "type": "Polygon",
      "coordinates": %s
    },
    "start_date": "%s",
    "end_date": "%s",
    "resolution": [
      "high","medium"
    ],
    "coverage": 50,
    "interval_length": 0,
    "order_by": [
      "resolution"
    ]
  }""" % (coords, startDate, endDate)

  #Start the search
  response = requests.post(sw_request, headers=headers, data=data)

  #Get the search ID for follow-up
  j = response.json()
  search_id=j['data']['id']

  status = 202
  while status == 202:
    time.sleep(3.0)
    headers = {'x-api-key': sw_key}
    sw_request = sw_url + "/archive/search/%s/search_results" % (search_id)
    response = requests.get(sw_request, headers=headers)
    status = response.status_code
  if status != 200:
    return([])
  else:
    j = response.json()
    results = {}
    if(int(j['pagination']['count'])  > 0):
      for item in j['data']:
        #print("Found {} imagery at {}".format(item['source'],item['start_time']))
        if item['source'] not in results:
          results[item['source']] = []
        results[item['source']].append(item['start_time'])
        results[item['source']].sort(reverse=False)
    return results

def searchAll(lat, lon, startDate,endDate):
  #Search via SentinelHub API
  spacecraft = ["SPOT","PHR","MAXAR","PLANET"]
  results = {}
  for sc in spacecraft:
    searchResults = imageSearch(lat, lon, sc, startDate, endDate)
    searchResults.sort(reverse=False)
    if searchResults:
      results[sc] = searchResults
  #Search via Skywach API
  skyResults = skywatchSearch(lat, lon, startDate, endDate)
  results.update(skyResults)
  return results

def PrintLastImages(results):
  #Pass a "results" dict and print out the last image per platform
  for i in results:
    print("{:<25} {:^25}".format(i,results[i].pop()).ljust(40), end='')
    print()


#Search past X days
numDays = 90
minusDays = datetime.today() - timedelta(days = numDays )
today   = datetime.today()
start_s = (minusDays.isoformat(timespec='seconds')+"Z")
end_s = (today.isoformat(timespec='seconds')+"Z")
spacecraft = ["SPOT","PHR","MAXAR","PLANET"]

latLonList = [[47.1015, 37.5968],[46.6872, 32.5119],[46.0763, 30.4698],[46.8556, 29.6006],[47.8731, 35.3017],[49.9909, 36.2314],[44.6047, 33.5334],[47.244, 38.847],[49.1531, 37.2497],[50.599, 36.597],[46.8775, 35.3086]]

for ll in latLonList:
  lat, lon = ll[0], ll[1]

  try:
    locationName = getNameFromLatLon(lat, lon)
  except:
    locationName = "(Unknown)"

  print(("\nSearching for most recent imagery within 2.5km of {} {} ({}) from {} until {}...").format(lat, lon, locationName, start_s, end_s))
  results = searchAll(lat, lon, start_s,end_s)
  PrintLastImages(results)



