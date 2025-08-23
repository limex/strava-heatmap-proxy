# strava-heatmap-proxy

This software allows streaming high resolution [Strava Global Heatmap](https://www.strava.com/maps/global-heatmap) tiles with clients like [QGIS](https://qgis.org/de/site/), [QMapShack](https://github.com/Maproom/qmapshack/wiki), [JOSM](https://josm.openstreetmap.de/) and many others without requiring them to be able to handle the Strava specific authentication and session management.

To do so, you need the following two pieces:
1. The [strava-cookie-exporter](#using-the-browser-extension) browser extension to export the necessary cookies as json file
1. The [strava-heatmap-proxy](#using-the-proxy-server) server which adds the necessary cookies to your requests before redirecting them to Strava

Note: [Previous versions](https://github.com/patrickziegler/strava-heatmap-proxy/tree/v1) of this repository were able to login to Strava automatically when running the proxy server.
Due to recent changes on Strava side this is not possible anymore and we need to extract (at least) a valid session identifier via the browser extension.
The proxy will then automatically refresh CloudFront tokens in case they have expired.

## Getting started

### Build and Install

With [git](https://git-scm.com/downloads), [golang](https://go.dev/) and [make](https://www.gnu.org/software/make/) available on your system, the following steps are sufficient to build and install `strava-heatmap-proxy` to the given path `INSTALL_PREFIX`:

```sh
git clone https://github.com/limex/strava-heatmap-proxy
cd strava-heatmap-proxy
INSTALL_PREFIX=~/.local/bin make install
```

### Using the browser extension

You can install the `strava-cookie-exporter` extension for Firefox from the Mozilla add-on store [here](https://addons.mozilla.org/de/firefox/addon/strava-cookie-exporter/).

With this extension installed, you can:
- Use your browser to login and navigate to the [Strava Global Heatmap](https://www.strava.com/maps/global-heatmap)
- Use the `strava-cookie-exporter` extension to export the relevant cookies as json file

The exported json file is needed for running [strava-heatmap-proxy](#using-the-proxy-server).

## Using the proxy server

Running the tool `strava-heatmap-proxy` from your terminal will set up a local proxy server for `https://content-a.strava.com/`.
Every request to `http://localhost:8080/` will then be extended with session cookies before being forwarded to Strava.
You can configure different target URLs or port numbers via `--target` or `--port` as well.

By default, the necessary cookies are expected to be found in the file `${HOME}/.config/strava-heatmap-proxy/strava-cookies.json` (should be manually created with the `strava-cookie-exporter` extension).
You can configure different locations of that file via `--cookies` as well.

The CloudFront cookies have an expiration period of 24 hours, but you don't need to recreate the `strava-cookies.json` file all the time because `strava-heatmap-proxy` can automatically refresh expired cookies as long as the session is valid (the exact duration of that is unkown right now).

### In GIS, QMapShack

To use this with your GIS software of choice, just define a simple [TMS](https://wiki.openstreetmap.org/wiki/TMS) layer like shown below that fetches high resolution heatmap tiles:

```xml
<TMS>
  <Title>StravaGlobalHeatmap</Title>
  <MinZoomLevel>5</MinZoomLevel>
  <MaxZoomLevel>16</MaxZoomLevel>
  <Layer idx="0">
    <ServerUrl>http://localhost:8080/identified/globalheat/all/bluered/%1/%2/%3.png?v=19</ServerUrl>
  </Layer>
</TMS>
```

This is how the result might look like in [QMapShack](https://github.com/Maproom/qmapshack/wiki):

![screenshot](https://addons.mozilla.org/user-media/previews/full/327/327795.png)


## in bikerouter.de

Add `http://localhost:8080/identified/globalheat/all/bluered/{z}/{x}/{y}.png?v=19` in a Custom Layer  

other Sports ...

```txt
http://localhost:8080/identified/globalheat/sport_Hike/hot/{z}/{x}/{y}.png?v=19
http://localhost:8080/identified/globalheat/sport_Ride/hot/{z}/{x}/{y}.png?v=19
http://localhost:8080/identified/globalheat/sport_MountainBikeRide/hot/{z}/{x}/{y}.png?v=19
http://localhost:8080/identified/globalheat/sport_Run/hot/{z}/{x}/{y}.png?v=19
http://localhost:8080/identified/globalheat/sport_GravelRide/hot/{z}/{x}/{y}.png?v=19
http://localhost:8080/identified/globalheat/ride/hot/15/{z}/{x}/{y}.png?v=19
http://localhost:8080/identified/globalheat/water/hot/15/{z}/{x}/{y}.png?v=19
http://localhost:8080/identified/globalheat/sport_BackcountrySki/{z}/{x}/{y}.png?v=19
http://localhost:8080/identified/globalheat/sport_NordicSki/hot/{z}/{x}/{y}.png?v=19
```


## More Examples actual tiles

adopt the Z/X/Y part (/15/17793/11515) accordingly to your need.

```txt
http://localhost:8080/identified/globalheat/sport_Hike/hot/15/17793/11515.png?v=19
http://localhost:8080/identified/globalheat/sport_Ride/hot/15/17793/11514.png?v=19
http://localhost:8080/identified/globalheat/sport_MountainBikeRide/hot/15/17793/11515.png?v=19
http://localhost:8080/identified/globalheat/sport_Run/hot/15/17793/11515.png?v=19
http://localhost:8080/identified/globalheat/sport_GravelRide/hot/15/17794/11514.png?v=19
http://localhost:8080/identified/globalheat/ride/hot/15/17794/11514.png?v=19
http://localhost:8080/identified/globalheat/water/hot/15/17792/11514.png?v=19
http://localhost:8080/identified/globalheat/sport_BackcountrySki/hot/11/1112/719.png?v=19
http://localhost:8080/identified/globalheat/sport_NordicSki/hot/9/277/179.png?v=19
```

## FAQ

### I get `listen tcp :8080: bind: address already in use`

```txt
# Find the process using port 8080
lsof -ti:8080

# Kill the process (replace PID with actual process ID)
kill $(lsof -ti:8080)

# Or force kill if needed
kill -9 $(lsof -ti:8080)
```

## Changes after forking 

- Fixed Issue is Browser Extension, that prevented usage in Chrome.
- Update to Go 1.25

## References

1. Original repo of Patrick Ziegler https://github.com/patrickziegler/strava-heatmap-proxy 
1. Discussion in https://github.com/bertt/wmts/issues/2 revealed the meaning of `CloudFront-*` tokens
1. https://github.com/erik/strava-heatmap-proxy was following a similar approach but is designed to be a Cloudflare worker

## License

This project is licensed under the GPL - see the [LICENSE](LICENSE) file for details


