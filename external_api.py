#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import sys

external_api_calls_path = (os.getcwd().replace("external_api", "external_api_calls"))
sys.path.append(external_api_calls_path)
from androguard.misc import *
from external_api_calls.androguard.core.androconf import *


def get_api_calls(x):
    '''
    :param x: a vm instance 
    :return: an external methods' list 
    '''
    top20Api = ['Landroid/telephony/SmsManager.sendTextMessage',
                'Landroid/telephony/TelephonyManager.getLine1Number',
                'Landroid/telephony/TelephonyManager.getSubscriberId',
                'Landroid/app/Service.onCreate',
                'Landroid/app/Service.onDestroy',
                'Landroid/app/Service.<init>',
                'Landroid/telephony/TelephonyManager.getDeviceId',
                'Landroid/content/Context.startService',
                'Landroid/content/pm/PackageManager',
                'Landroid/telephony/SmsManager.getDefault',
                'Ljava/util/Timer.<init>',
                'Landroid/os/Bundle.get',
                'Landroid/content/pm/ApplicationInfo.loadLabel',
                'Ljava/lang/Process.getOutputStream',
                'Ljava/lang/Runtime.exec',
                'Ljava/util/TimerTask.<init>',
                'Ljava/io/DataOutputStream.flush',
                'Ljava/io/FileOutputStream.flush',
                'Ljava/lang/Process.waitFor',
                'Landroid/net/NetworkInfo.get']
    counter = 0
    a, d, dx = AnalyzeAPK(x)
    methods = []
    external_classes = dx.get_external_classes()  # XREFFROM to XREFTo
    for i in external_classes:
        class_name = i.get_vm_class()
        methods_list = class_name.get_methods()
        for method in methods_list:
            a = "%s" % method.get_class_name()
            b = "%s" % method.get_name()
            c = "%s" % method.get_descriptor()
            method_name = a.rstrip(";") + "." + b + c
            if any(sentence in method_name for sentence in top20Api):
                methods.append(method_name)
                counter += 1
            else:
                methods.append(method_name)
    methods.append("-------------------------------------------------SusExternalAPI: "+str(counter))
    return list(set(methods))


# if __name__ == "__main__":
#     apk_dir = "SampleApplication.apk"
#     a = get_api_calls(apk_dir)
#     print(len(get_api_calls(apk_dir)), get_api_calls(apk_dir))
