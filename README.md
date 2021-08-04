# GDPR-Consent
Code for our paper: "Share First, Ask Later (or Never?) - Studying Violations of GDPR's Explicit Consent in Android Apps"

Overview: Our main goal is to have a mostly automated and scalable solution to detect personal data that is being sent to the Internet without users’ explicit consent, as is mandated by the GDPR. We set up an array of Android devices, on which we run each app (without any interaction) and capture the network traffic. Based on personal data which is directly tied to the phone, we automatically detect this data in both plain and encoded form through string matching. Further, we derive a methodology that allows us to pinpoint data that may be other unique identifiers and manually validate whether this can be used to track the user/device.

![alt text](overview_workflow.png)

# Prerequisite
1. A rooted Android device (note that all of our testing has been taking place on a Pixels, Pixel 3a, and Nexus
5 that are running Android 8 or 9).
2. Installing Frida for your devices (see this tutorial https://frida.re/docs/android/)
3. Installing mitmproxy for your server as well as the mitmproxy CA certificate has to be installed on the client Android devices (see this documentation https://docs.mitmproxy.org/stable/)

# How to Install
1. Clone this repository and install all the dependencies with pip (`pip install -r requirements.txt`)
2. Started the Frida server on your Android devices
3. Configuring a Proxy server on your Android devices

# How to Use
1. Network Traffic Analysis: . In the first step of our analysis pipeline, we aim to identify apps that send some data when started. To achieve that, we install the app in question and grant all requested permissions listed in the manifest, i.e., both install time and runtime permissions. Subsequently, we launch the app and record its network traffic.

`python network-traffic-analysis.py -s FA6AL0309000 -p 8080 -f apk_file_input.csv -o output/`

| Parameter  | Description |
| ------------- | ------------- |
| -s  | The Android device serial number  |
| -p  | The port of proxy server  |
| -f  | The csv file that contains package name and the corresponding path to the apk file. For example: each line in this csv file is a `"package_name","file_path"`  |
| -o  | The output directory |

2.  Traffic Log Analyzer: The second step is to identify personal data that is tied to the phone, such as the location, the AAID, or the MAC address. Since such information is accessible by apps, we extract the relevant values from the phone through the Android debug bridge to ensure we know these values for each phone.

| Data Type  | Description |
| ------------- | ------------- |
|AAID | Android Advertising ID|
|BSSID | Router MAC addresses of nearby hotspots|
|Email | Email address of phone owner|
|GPS | User location|
|IMEI | Mobile phone equipment ID|
|IMSI | SIM card ID|
|MAC | MAC address of WiFi interface|
|PHONE | Mobile phone’s number|
|SIM_SERIAL | SIM card ID|
|SERIAL | Phone hardware ID (serial number)|
|SSID | Router SSIDs of nearby hotspots|
|GSF ID | Google Services Framework ID|
