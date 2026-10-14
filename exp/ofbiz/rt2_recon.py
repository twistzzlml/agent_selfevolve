# -*- coding: utf-8 -*-
"""RT-2 recon: 交叉分析 controller request-map(auth=false) -> view -> screen -> decorator 名。"""
import glob
import io
import os
import re
import xml.etree.ElementTree as ET

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_src")

# 1) request-maps + view-maps from all controllers
controllers = glob.glob(os.path.join(SRC, "framework", "common", "webcommon",
                                     "WEB-INF", "*.xml")) + \
    glob.glob(os.path.join(SRC, "framework", "webtools", "webapp", "webtools",
                           "WEB-INF", "controller.xml"))
requests = {}   # uri -> (views dict, auth)
viewmaps = {}   # view name -> page
for c in controllers:
    root = ET.parse(c).getroot()
    for vm in root.findall("view-map"):
        viewmaps[vm.get("name")] = vm.get("page")
    for rm in root.findall("request-map"):
        uri = rm.get("uri")
        views = {}
        auth = None
        for resp in rm.findall("response"):
            views[resp.get("name")] = resp.get("value", "")
        sec = rm.find("security")
        if sec is not None:
            auth = sec.get("auth")
        requests[uri] = (views, auth)

print("== view-maps total:", len(viewmaps), " requests:", len(requests))

# 2) screens using parameters.<x>DecoratorLocation -> expected decorator name
screen_dir = os.path.join(SRC, "framework")
pat = re.compile(r'<decorator-screen[^>]*name="([^"]+)"[^>]*'
                 r'location="\$\{parameters\.(\w+)\}"')
pat2 = re.compile(r'<decorator-screen[^>]*location="\$\{parameters\.(\w+)\}"'
                  r'[^>]*name="([^"]+)"')
screen_names = {}   # screen name -> (decorator screen name, param name)
for path in glob.glob(os.path.join(screen_dir, "**", "*.xml"), recursive=True):
    try:
        text = io.open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    if "Widget-Screen" not in text and "<screen" not in text:
        continue
    root = None
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        pass
    if root is None:
        continue
    for scr in root.iter("screen"):
        sname = scr.get("name")
        for w in scr.iter():
            if w.tag == "decorator-screen":
                loc = w.get("location") or ""
                m = re.search(r"\$\{parameters\.(\w+)\}", loc)
                if m:
                    screen_names[sname] = (w.get("name"), m.group(1),
                                           os.path.relpath(path, SRC))

print("== screens w/ parameterized decorator:")
for s, v in sorted(screen_names.items()):
    print("  screen %-40s decorator=%-28s param=%s" % (s, v[0], v[1]))

# 3) unauth requests whose view maps to such screens
print("== unauth request -> screen -> needed decorator/param:")
for uri, (views, auth) in sorted(requests.items()):
    if auth != "false":
        continue
    for rname, view in views.items():
        page = viewmaps.get(view)
        if not page:
            continue
        # page like component://webtools/widget/MiscScreens.xml#ViewHelpers
        if "#" not in page:
            continue
        loc, sname = page.split("#", 1)
        if sname in screen_names:
            dec, param, rel = screen_names[sname]
            print("  /webtools/control/%-42s view=%-24s screen=%-30s"
                  " decorator=%-24s param=%s" % (uri, view, sname, dec, param))
